//go:build offensive

// Package pbxhttp implements the offensive write-gate proxy for
// HTTP(S) PBX admin UIs.
//
// Architecture mirrors offensive/write/sip (ADR-040 template): per-
// session Authorise on the SHA-256 of a sorted allowlist, per-
// request filtering via net/http's server-side parser. The HTTP
// specifics:
//
//   - The default proxy (internal/protocols/pbxhttp) refuses every
//     client byte with `HTTP/1.1 403 Forbidden`. This handler is the
//     gated variant that replaces that default only when `-tags
//     offensive` is built AND the three operator fences pass
//     (--accept-writes + --confirm-target + --confirm-token).
//   - Read-only HTTP methods (GET / HEAD / OPTIONS) always pass
//     unchanged. They don't mutate state and operators need them to
//     navigate the admin UI before committing a write.
//   - State-changing methods (POST / PUT / PATCH / DELETE) are gated
//     against an operator-supplied (method, path) allowlist. An
//     entry matches when the request's method AND its URL path
//     EXACTLY equal the allowlist entry. Glob / prefix matching
//     comes later once field hours inform a pattern syntax.
//   - Refusal path depends on the failure mode:
//     method not in the always-safe set and no allowlist entry
//     matches the method alone → 405 Method Not Allowed with an
//     `Allow:` header listing GET/HEAD/OPTIONS plus any
//     allowlisted methods.
//     method matches but the path does not → 403 Forbidden.
//     Both carry a `Content-Length: 0` body and `Connection: close`.
//   - CONNECT (for TLS tunnelling via a forward proxy) is
//     explicitly refused — the gate can't inspect tunnelled traffic
//     and the operator should configure the upstream directly when
//     they need TLS.
//
// Out of scope for v1.4 chunk 2 (deferred to v1.5+): prefix /
// glob matching in paths (useful for REST APIs with IDs);
// query-string allowlisting; body-content inspection (e.g.
// FreePBX's /admin/config.php?display=general vs a destructive
// admin action on the same path); Host header enforcement (we're
// a single-target proxy today).
package pbxhttp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"local/elsereno/offensive/confirm"
)

// AllowedWrite is one (method, path) pair the operator has
// authorised for the session. Both fields are canonicalised
// (method upper-case, path prefixed with "/") on hash + compare.
// An empty allowlist forbids every state-changing method; read-
// only methods still pass.
type AllowedWrite struct {
	// Method is a state-changing HTTP method (POST / PUT /
	// PATCH / DELETE). Read-only methods (GET / HEAD / OPTIONS)
	// do not need to be listed.
	Method string
	// Path is the exact URL path (starting with "/"). No glob
	// or prefix; the path in the incoming request must equal
	// this byte-for-byte after canonicalisation.
	Path string
}

// AllowlistHash returns the deterministic SHA-256 of the
// allowlist. Entries are canonicalised (method upper-case, path
// untouched beyond trim) and sorted lexicographically by
// `METHOD<NUL>PATH` before hashing so the operator's dry-run
// token is stable regardless of input order / case.
func AllowlistHash(target string, allowed []AllowedWrite) [32]byte {
	keys := make([]string, 0, len(allowed))
	for _, a := range allowed {
		m := strings.ToUpper(strings.TrimSpace(a.Method))
		p := strings.TrimSpace(a.Path)
		keys = append(keys, m+"\x00"+p)
	}
	sort.Strings(keys)
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises the
// proxy session for target + allowlist. Same shape as the modbus
// / s7 / opcua / sip templates so the CLI wiring stays uniform.
func SessionMutation(target string, allowed []AllowedWrite) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "pbxhttp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// readOnlyMethods lists the HTTP methods that always pass,
// regardless of the operator's allowlist. Canonical upper-case.
var readOnlyMethods = map[string]struct{}{
	http.MethodGet:     {},
	http.MethodHead:    {},
	http.MethodOptions: {},
}

// WriteGatedHandler is the offensive replacement for the default
// pbxhttp deny-all proxy. Construction requires triple-confirm
// authorised session context.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the (method, path) allowlist authorised at
	// session open. Empty → only read-only methods pass.
	Allowed []AllowedWrite
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
// Handle.
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
var ErrSessionNotAuthorised = errors.New("pbxhttp: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. Parses requests from the
// client with net/http's server-side parser, applies the gate,
// and forwards allowed requests to upstream while returning the
// upstream response to the client.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	br := bufio.NewReader(client)
	upReader := bufio.NewReader(upstream)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("pbxhttp: read request: %w", err)
		}
		done, err := h.handleOne(ctx, req, client, upstream, upReader)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// handleOne processes a single parsed request. Returns (done,
// err) where done=true signals the caller to stop the loop
// (Connection: close, context cancellation, etc.).
func (h *WriteGatedHandler) handleOne(ctx context.Context, req *http.Request, client, upstream io.Writer, upReader *bufio.Reader) (bool, error) {
	// CONNECT is always refused (see package doc).
	if req.Method == http.MethodConnect {
		if err := writeForbidden(client, "CONNECT tunnelling is not supported by the gated proxy"); err != nil {
			return true, err
		}
		return false, nil
	}

	pass, ref := h.gate(req)
	if !pass {
		if err := writeRefusal(client, ref); err != nil {
			return true, err
		}
		if req.Body != nil {
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
		}
		return false, nil
	}

	// Forward the full request (headers + body) to upstream.
	// http.Request.Write handles Content-Length / chunked / keep-
	// alive framing.
	if err := req.Write(upstream); err != nil {
		return true, fmt.Errorf("pbxhttp: forward request: %w", err)
	}

	// Read the upstream response + write it back to client.
	resp, err := http.ReadResponse(upReader, req)
	if err != nil {
		return true, fmt.Errorf("pbxhttp: read upstream response: %w", err)
	}
	writeErr := resp.Write(client)
	_ = resp.Body.Close()
	if writeErr != nil {
		return true, fmt.Errorf("pbxhttp: forward response: %w", writeErr)
	}

	if req.Close || resp.Close {
		return true, nil
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	return false, nil
}

// refusal describes a gate denial.
type refusal struct {
	code   int    // 405 or 403
	reason string // log-friendly reason
	allow  string // "GET, HEAD, …" — only populated on 405
}

// gate makes the per-request policy decision. Returns (true, _)
// to forward; (false, reason) to refuse.
func (h *WriteGatedHandler) gate(req *http.Request) (bool, refusal) {
	method := strings.ToUpper(req.Method)
	if _, ok := readOnlyMethods[method]; ok {
		return true, refusal{}
	}
	// Does any allowlist entry use this method? If no entry for
	// this method exists at all, that's a 405 (method not
	// permitted on this proxy).
	methodFound := false
	for _, a := range h.Allowed {
		if strings.ToUpper(strings.TrimSpace(a.Method)) == method {
			methodFound = true
			break
		}
	}
	if !methodFound {
		return false, refusal{
			code:   http.StatusMethodNotAllowed,
			reason: "method " + method + " is not in the session allowlist",
			allow:  h.allowedMethodsList(),
		}
	}
	// Method is allowed in principle — check the path.
	for _, a := range h.Allowed {
		if strings.ToUpper(strings.TrimSpace(a.Method)) == method &&
			strings.TrimSpace(a.Path) == req.URL.Path {
			return true, refusal{}
		}
	}
	return false, refusal{
		code:   http.StatusForbidden,
		reason: "path " + req.URL.Path + " is not in the session allowlist for " + method,
	}
}

// allowedMethodsList returns the full Allow: header value string
// (read-only methods + distinct allowlisted methods, comma-
// separated, sorted).
func (h *WriteGatedHandler) allowedMethodsList() string {
	set := map[string]struct{}{}
	for k := range readOnlyMethods {
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

// writeRefusal emits a canonical HTTP response conveying the
// refusal. 405 carries the Allow: header; 403 does not.
func writeRefusal(w io.Writer, r refusal) error {
	var b strings.Builder
	switch r.code { //nolint:exhaustive // only 403 + 405 are emitted by the gate
	case http.StatusMethodNotAllowed:
		b.WriteString("HTTP/1.1 405 Method Not Allowed\r\n")
		if r.allow != "" {
			b.WriteString("Allow: ")
			b.WriteString(r.allow)
			b.WriteString("\r\n")
		}
	case http.StatusForbidden:
		b.WriteString("HTTP/1.1 403 Forbidden\r\n") //nolint:misspell // RFC 7235 canonical spelling
	default:
		// Defensive — never reached.
		b.WriteString("HTTP/1.1 500 Internal Server Error\r\n")
	}
	b.WriteString("Server: ElSereno proxy (gated, offensive)\r\n")
	if r.reason != "" {
		b.WriteString("X-Elsereno-Gate-Reason: ")
		b.WriteString(strings.ReplaceAll(r.reason, "\r\n", " "))
		b.WriteString("\r\n")
	}
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// writeForbidden is a thin wrapper for the CONNECT special-case +
// any future one-off refusals that don't carry an Allow header.
func writeForbidden(w io.Writer, reason string) error {
	return writeRefusal(w, refusal{code: http.StatusForbidden, reason: reason})
}
