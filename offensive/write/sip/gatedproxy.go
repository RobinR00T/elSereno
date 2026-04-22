//go:build offensive

// Package sip implements the offensive write-gate proxy for SIP
// (RFC 3261).
//
// Architecture mirrors offensive/write/opcua + offensive/write/modbus
// (the ADR-040 template): per-session Authorise on the SHA-256 of a
// sorted allowlist, per-request filtering at wire-parse time. The
// SIP specifics:
//
//   - The default proxy (internal/protocols/sip) refuses every client
//     byte with `SIP/2.0 403 Forbidden`. This handler is the gated
//     variant that replaces that default only when `-tags offensive`
//     is built AND the three operator fences (--accept-writes +
//     --confirm-target + --confirm-token) pass.
//   - Every SIP request begins with a request-line: `METHOD URI
//     SIP/2.0\r\n`. The gate reads the request-line + headers via
//     net/textproto, checks Method against the allowlist, then
//     forwards the entire request (headers + Content-Length body)
//     to the upstream or emits a 405 back to the client.
//   - Methods that are always safe to forward (never gated):
//     OPTIONS — probe; no side effects.
//     ACK     — part of the INVITE three-way; required for
//     dialog completion AFTER an INVITE the operator
//     already allowed.
//     BYE     — dialog teardown. Blocking BYE would leak
//     resources on both sides.
//     CANCEL  — cancels a pending INVITE; analogous to BYE.
//     PRACK   — provisional ACK for reliable 1xx.
//   - Methods the operator explicitly gates:
//     INVITE        — toll fraud, call hijack.
//     REGISTER      — registration hijack.
//     MESSAGE       — SMS-over-SIP spam / phish.
//     SUBSCRIBE     — presence/event data exfil.
//     NOTIFY        — forged event injection.
//     REFER         — call transfer (can redirect to attacker).
//     PUBLISH       — presence state forgery.
//     UPDATE        — session modify mid-dialog.
//     INFO          — mid-dialog DTMF / app info.
//   - Refusal path is a canonical SIP 405 Method Not Allowed with
//     an `Allow:` header listing the always-safe methods plus any
//     allowlisted methods. Real SIP clients parse 405 correctly
//     and back off without retrying.
//
// Out of scope for v1.4 chunk 1: INVITE To-header allowlist (toll-
// destination blocking by dialled E.164 prefix), REGISTER AOR
// allowlist (binding-specific allowlisting), per-From-URI policies.
// These are v1.5+ once the method-level gate has field-time hours.
package sip

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sort"
	"strconv"
	"strings"

	"local/elsereno/offensive/confirm"
)

// AllowedMethod is one SIP method the operator has authorised for
// the session. An empty allowlist forbids every gated method
// (equivalent to the default deny-all proxy, but with a 405
// refusal instead of a 403 — slightly gentler for real SIP
// clients).
type AllowedMethod struct {
	// Method is the canonical upper-case SIP method (INVITE,
	// REGISTER, MESSAGE, SUBSCRIBE, NOTIFY, REFER, PUBLISH,
	// UPDATE, INFO). Always-safe methods (OPTIONS/ACK/BYE/
	// CANCEL/PRACK) do not need to be listed.
	Method string
}

// AllowlistHash returns the deterministic SHA-256 of the
// allowlist. Methods are canonicalised to upper case and sorted
// alphabetically before hashing so the operator's dry-run token
// is stable regardless of input order / case.
func AllowlistHash(target string, allowed []AllowedMethod) [32]byte {
	sorted := make([]string, 0, len(allowed))
	for _, a := range allowed {
		sorted = append(sorted, strings.ToUpper(strings.TrimSpace(a.Method)))
	}
	sort.Strings(sorted)
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, m := range sorted {
		_, _ = h.Write([]byte(m))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises the
// proxy session for target + allowlist. Same shape as the modbus
// / s7 / opcua templates so the CLI wiring stays uniform.
func SessionMutation(target string, allowed []AllowedMethod) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "sip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// alwaysSafeMethods lists the SIP methods that always pass,
// regardless of the operator's allowlist. Canonical upper-case.
var alwaysSafeMethods = map[string]struct{}{
	"OPTIONS": {},
	"ACK":     {},
	"BYE":     {},
	"CANCEL":  {},
	"PRACK":   {},
}

// WriteGatedHandler is the offensive replacement for the default
// SIP deny-all proxy. Construction requires triple-confirm
// authorised session context (Deriver, Auditor, and the
// session-level Confirm struct). The handler does NOT
// re-authorise per request — it parses the SIP request-line per
// message and allows (a) alwaysSafeMethods always, (b) any method
// in the operator-supplied allowlist.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the list of SIP methods the operator authorised
	// at session open. Empty list forbids every gated method;
	// always-safe methods still pass.
	Allowed []AllowedMethod
	// Deriver + Auditor drive the session-open Authorize call.
	Deriver confirm.KeyDeriver
	Auditor confirm.Auditor
	// SessionConfirm is the Confirm struct the CLI populates
	// from --accept-writes / --confirm-target / --confirm-token.
	SessionConfirm confirm.Confirm

	// authorised flips true after a successful Authorise.
	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle. Returns the same error set as confirm.Authorize so the
// CLI can route.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("sip: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. Splits into two goroutines:
// the client→upstream stream is parsed + gated per request; the
// upstream→client stream is a straight io.Copy (responses are
// never gated — operators always want to see what upstream
// replied, so they can notice a successful call even if the gate
// slipped).
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream, client) }()
	go func() {
		_, err := io.Copy(client, upstream)
		errs <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// forward reads one SIP request at a time from the client and
// routes per policy.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	br := bufio.NewReader(client)
	tp := textproto.NewReader(br)
	for {
		// Read the request-line. On EOF (client hung up), return
		// gracefully.
		line, err := tp.ReadLine()
		if err != nil {
			return err
		}
		// Skip blank lines (SIP tolerates inter-message CRLF as
		// keep-alive).
		if line == "" {
			continue
		}
		// Guard: response-lines start with SIP/. The gate
		// expects requests from the client. If we see a
		// response, the client is misbehaving — log-worthy but
		// not fatal; forward it so the upstream can decide.
		if strings.HasPrefix(line, "SIP/") {
			// Rebuild the full head + body and copy through.
			if err := passthroughRawHead(line, tp, upstream); err != nil {
				return err
			}
			continue
		}

		method, ok := parseMethod(line)
		if !ok {
			return fmt.Errorf("sip: malformed request-line %q", truncate(line, 64))
		}

		// Read headers into a MIMEHeader so we can honour
		// Content-Length for the body.
		headers, err := tp.ReadMIMEHeader()
		if err != nil {
			return fmt.Errorf("sip: read headers: %w", err)
		}
		bodyLen, err := parseContentLength(headers.Get("Content-Length"))
		if err != nil {
			return err
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(br, body); err != nil {
				return fmt.Errorf("sip: read body: %w", err)
			}
		}

		if h.allow(method) {
			if err := writeRequest(upstream, line, headers, body); err != nil {
				return err
			}
			continue
		}
		// Refuse: emit a 405 back to the client. Drop the body
		// (already consumed above).
		if err := writeMethodNotAllowed(clientWriter, headers, h.allowedMethodsList()); err != nil {
			return err
		}
	}
}

// allow reports whether the given SIP method is authorised for
// this session. Method is canonicalised before comparison.
func (h *WriteGatedHandler) allow(method string) bool {
	m := strings.ToUpper(strings.TrimSpace(method))
	if _, ok := alwaysSafeMethods[m]; ok {
		return true
	}
	for _, a := range h.Allowed {
		if strings.ToUpper(strings.TrimSpace(a.Method)) == m {
			return true
		}
	}
	return false
}

// allowedMethodsList returns the full Allow: header value string
// (always-safe + operator allowlist, comma-separated, sorted).
func (h *WriteGatedHandler) allowedMethodsList() string {
	set := map[string]struct{}{}
	for k := range alwaysSafeMethods {
		set[k] = struct{}{}
	}
	for _, a := range h.Allowed {
		m := strings.ToUpper(strings.TrimSpace(a.Method))
		if m != "" {
			set[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// parseMethod extracts the first SP-delimited token of a SIP
// request-line. Returns (METHOD, true) on success.
func parseMethod(line string) (string, bool) {
	idx := strings.IndexByte(line, ' ')
	if idx <= 0 {
		return "", false
	}
	method := line[:idx]
	// Must be at least one request URI + SIP/2.0 after.
	if !strings.HasSuffix(line, " SIP/2.0") && !strings.Contains(line, " SIP/2.0 ") {
		return "", false
	}
	return method, true
}

// parseContentLength parses the Content-Length header value. An
// empty/missing header is treated as length 0 (valid for
// OPTIONS, REGISTER without body, etc.).
func parseContentLength(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("sip: bad Content-Length %q: %w", v, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("sip: negative Content-Length %d", n)
	}
	if n > maxBodyLen {
		return 0, fmt.Errorf("sip: Content-Length %d exceeds %d-byte limit", n, maxBodyLen)
	}
	return n, nil
}

// maxBodyLen caps a single SIP message body at 1 MiB. Real
// SIP/SDP bodies are under 2 KiB; the cap is a defence against a
// compromised client trying to starve the proxy.
const maxBodyLen = 1 << 20

// writeRequest re-serialises an allowed request onto the
// upstream. Headers are sorted alphabetically for determinism —
// SIP is header-order-insensitive at the server side per RFC 3261
// §7.3.1.
func writeRequest(w io.Writer, requestLine string, headers textproto.MIMEHeader, body []byte) error {
	var b strings.Builder
	b.WriteString(requestLine)
	b.WriteString("\r\n")

	// Serialise headers in canonical order. Content-Length is
	// written last and overridden to match the actual body.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range headers.Values(k) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("Content-Length: ")
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteString("\r\n\r\n")

	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// writeMethodNotAllowed emits a SIP 405 back to the client. The
// Allow header lists all always-safe + allowlisted methods, so
// the client can retry with a permitted verb. Via / From / To /
// Call-ID / CSeq are echoed from the request per RFC 3261
// §8.2.6.1. Content-Length is 0.
func writeMethodNotAllowed(w io.Writer, reqHeaders textproto.MIMEHeader, allowHeader string) error {
	var b strings.Builder
	b.WriteString("SIP/2.0 405 Method Not Allowed\r\n")
	// Echo routing headers from the request so the client can
	// correlate the response to its transaction.
	for _, k := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
		for _, v := range reqHeaders.Values(k) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("Allow: ")
	b.WriteString(allowHeader)
	b.WriteString("\r\n")
	b.WriteString("Server: ElSereno proxy (gated, offensive)\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// passthroughRawHead forwards a response (SIP/… line + headers +
// body) from client to upstream without inspection. Used only
// when the client happens to send a response-line to the server
// (which violates SIP but can happen from buggy UACs — we want
// to stay transparent).
func passthroughRawHead(statusLine string, tp *textproto.Reader, w io.Writer) error {
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return err
	}
	bodyLen, err := parseContentLength(headers.Get("Content-Length"))
	if err != nil {
		return err
	}
	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(tp.R, body); err != nil {
			return err
		}
	}
	var b strings.Builder
	b.WriteString(statusLine)
	b.WriteString("\r\n")
	for k := range headers {
		for _, v := range headers.Values(k) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if len(body) > 0 {
		_, err := w.Write(body)
		return err
	}
	return nil
}

// truncate caps s at n runes for safe log display.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
