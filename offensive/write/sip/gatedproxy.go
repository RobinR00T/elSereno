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
// v1.9 chunk 5 added INVITE To-URI prefix allowlist
// (`AllowedToURIPrefixes`) for toll-fraud mitigation. v1.10
// chunk 1 adds REGISTER AOR allowlist (`AllowedAORs`) for
// registration-hijack mitigation — pairs with the INVITE prefix
// list as the two sides of PBX-abuse gating:
//
//   - INVITE + prefix list  → controls WHERE calls can go.
//   - REGISTER + AOR list   → controls WHO can register a
//     binding to call upstream. Without this the operator must
//     trust that anyone who got through auth also got auth for
//     every AoR; with it, a stolen set of creds for `alice@pbx`
//     can't be used to hijack `admin@pbx`.
//
// Out of scope for v1.10 chunk 1: per-From-URI policies (restrict
// which registrars can reach the proxy in the first place),
// MESSAGE content allowlist, SUBSCRIBE / NOTIFY event-package
// allowlist. Those are v1.11+ once the AOR + prefix gates have
// field-time hours.
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

// AllowedToURIPrefix is one prefix the operator has authorised
// for INVITE destination numbers. When the handler's
// `AllowedToURIPrefixes` field is non-empty, INVITE requests
// pass only when the To: header's user-part starts with one of
// these prefixes.
//
// Typical use-case: toll-fraud mitigation. The method allowlist
// (`AllowedMethod{Method:"INVITE"}`) says "you can place
// outbound calls"; the prefix allowlist says "only to these
// destinations". Example: allow +34 (Spain) and +44 (UK)
// prefixes but refuse +900, +883 (premium-rate / mobile
// satellite) that are favourite toll-fraud targets.
//
// Prefixes are case-folded + trimmed before compare. Whitespace
// + SIP URI separators (`tel:`, `sip:`) are stripped from the
// candidate user-part before matching so operators can write
// clean prefixes without worrying about the inbound URI shape.
type AllowedToURIPrefix struct {
	// Prefix is the canonical form expected at the start of
	// the To: URI user-part. Leading "+" matters: "+34" only
	// matches E.164-prefixed numbers, "34" would also match
	// bare "34xxx" extensions.
	Prefix string
}

// AllowlistHash returns the deterministic SHA-256 of the
// method allowlist. Methods are canonicalised to upper case and
// sorted alphabetically before hashing so the operator's
// dry-run token is stable regardless of input order / case.
//
// v1.4 callers (method-only) keep the same hash they've always
// seen. Operators who opt into To-URI prefix gating use
// AllowlistHashWithPrefixes instead, which mixes both
// dimensions into the hash.
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

// AllowlistHashWithPrefixes is the v1.9 hash that incorporates
// both the method allowlist AND a sorted per-prefix allowlist.
// When prefixes is nil or empty, the hash is identical to
// AllowlistHash(target, methods) so v1.4 tokens remain valid
// for operators not opting into prefix gating.
//
// Hash layout:
//
//	target || 0x00 || METHOD<NUL> × sorted_methods
//	                    [|| 0xFF || PREFIX<NUL> × sorted_prefixes]
//
// The 0xFF separator cannot collide with a method byte (SIP
// methods are ASCII A-Z uppercase; 0xFF is outside that range).
func AllowlistHashWithPrefixes(target string, methods []AllowedMethod, prefixes []AllowedToURIPrefix) [32]byte {
	if len(prefixes) == 0 {
		return AllowlistHash(target, methods)
	}
	sortedMethods := make([]string, 0, len(methods))
	for _, m := range methods {
		sortedMethods = append(sortedMethods, strings.ToUpper(strings.TrimSpace(m.Method)))
	}
	sort.Strings(sortedMethods)

	sortedPrefixes := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		sortedPrefixes = append(sortedPrefixes, canonicalisePrefix(p.Prefix))
	}
	sort.Strings(sortedPrefixes)

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, m := range sortedMethods {
		_, _ = h.Write([]byte(m))
		_, _ = h.Write([]byte{0x00})
	}
	_, _ = h.Write([]byte{0xFF})
	for _, p := range sortedPrefixes {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises the
// proxy session for target + allowlist. Same shape as the modbus
// / s7 / opcua templates so the CLI wiring stays uniform. v1.4
// compatibility.
func SessionMutation(target string, allowed []AllowedMethod) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "sip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// SessionMutationWithPrefixes is the v1.9 Mutation that mixes
// both method + To-URI prefix allowlists into the PayloadHash.
// When prefixes is nil/empty it degrades to SessionMutation.
func SessionMutationWithPrefixes(target string, methods []AllowedMethod, prefixes []AllowedToURIPrefix) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "sip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithPrefixes(target, methods, prefixes),
	}
}

// AllowedAOR is one AOR (Address-of-Record) the operator has
// authorised for REGISTER. When the handler's `AllowedAORs`
// field is non-empty, REGISTER requests pass only when the
// To: header's URI (canonicalised, user@host form) exactly
// matches one of these entries.
//
// Typical use-case: registration-hijack mitigation. An attacker
// who captures SIP creds for one account (e.g. via phishing,
// WiFi sniff, or a compromised endpoint) would normally be
// able to register bindings for any AoR the upstream accepts —
// hijacking inbound calls for `admin@pbx` using `alice@pbx`'s
// stolen creds. With the AOR allowlist, REGISTER is scoped to
// the exact AoR(s) the operator expects to serve; any drift is
// a 403 with a traceable `X-Elsereno-Gate-Reason` header.
//
// AORs are case-folded + URI-scheme-stripped before compare so
// operators can write `sip:alice@example.com` or just
// `alice@example.com` — both canonicalise the same. The match
// is EXACT (not prefix), unlike the INVITE prefix gate — an
// attacker who gets `alice.evil@example.com` past the allowlist
// shouldn't also get `alice@example.com`.
type AllowedAOR struct {
	// AOR is the canonical address-of-record the operator
	// authorises. Accepts either bare `user@host` or fully-
	// qualified `sip:user@host` / `sips:user@host` /
	// `tel:user` form; the canonicaliser strips scheme + angle
	// brackets + lowercases.
	AOR string
}

// canonicaliseAOR normalises an AOR string for hashing +
// compare. Strips angle brackets, URI scheme (sip:/sips:/tel:),
// URI parameters (;tag=…), trims whitespace, and lowercases
// the host part while preserving the user part's case because
// RFC 3261 §19.1.1 says the user part is case-sensitive by
// default. (In practice most SIP stacks fold the user part too,
// but we stay conservative.)
//
// Returns empty string on malformed input.
func canonicaliseAOR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Angle brackets first.
	if i := strings.IndexByte(s, '<'); i >= 0 {
		j := strings.IndexByte(s[i+1:], '>')
		if j < 0 {
			return ""
		}
		s = s[i+1 : i+1+j]
	}
	// URI parameters.
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	// Scheme.
	lower := strings.ToLower(s)
	for _, scheme := range []string{"sips:", "sip:", "tel:"} {
		if strings.HasPrefix(lower, scheme) {
			s = s[len(scheme):]
			break
		}
	}
	// Split user@host, lowercase only host (user is
	// technically case-sensitive per RFC 3261 §19.1.1).
	if i := strings.IndexByte(s, '@'); i >= 0 {
		user := s[:i]
		host := strings.ToLower(s[i+1:])
		return user + "@" + host
	}
	// No '@' — likely a `tel:` that lost its scheme. Lowercase
	// the whole thing since there's no user/host distinction
	// to preserve.
	return strings.ToLower(s)
}

// AllowlistHashWithAORs is the v1.10 hash that incorporates the
// method allowlist, the optional INVITE To-URI prefix allowlist
// (v1.9), AND the optional REGISTER AOR allowlist (v1.10).
//
// Backwards compatibility: when both prefixes AND aors are
// empty, the hash equals `AllowlistHash(target, methods)` (v1.4
// plain). When only prefixes is non-empty, the hash equals
// `AllowlistHashWithPrefixes(target, methods, prefixes)` (v1.9
// variant). Only when aors is non-empty does the new layout
// kick in — existing tokens remain valid for operators who
// don't opt into AOR gating.
//
// New hash layout (when aors is non-empty):
//
//	target || 0x00 || METHOD<NUL> × sorted_methods
//	               [|| 0xFF || PREFIX<NUL> × sorted_prefixes]
//	                || 0xFE || AOR<NUL> × sorted_aors
//
// The 0xFE separator is chosen so it can't collide with a
// method byte (SIP methods are ASCII A-Z) nor with the 0xFF
// prefix-block separator. Decoders don't exist (this is a
// one-way hash), but the distinct separator keeps collision
// reasoning clean.
func AllowlistHashWithAORs(target string, methods []AllowedMethod, prefixes []AllowedToURIPrefix, aors []AllowedAOR) [32]byte {
	if len(aors) == 0 {
		return AllowlistHashWithPrefixes(target, methods, prefixes)
	}
	sortedMethods := make([]string, 0, len(methods))
	for _, m := range methods {
		sortedMethods = append(sortedMethods, strings.ToUpper(strings.TrimSpace(m.Method)))
	}
	sort.Strings(sortedMethods)

	sortedPrefixes := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		sortedPrefixes = append(sortedPrefixes, canonicalisePrefix(p.Prefix))
	}
	sort.Strings(sortedPrefixes)

	sortedAORs := make([]string, 0, len(aors))
	for _, a := range aors {
		if c := canonicaliseAOR(a.AOR); c != "" {
			sortedAORs = append(sortedAORs, c)
		}
	}
	sort.Strings(sortedAORs)

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, m := range sortedMethods {
		_, _ = h.Write([]byte(m))
		_, _ = h.Write([]byte{0x00})
	}
	if len(sortedPrefixes) > 0 {
		_, _ = h.Write([]byte{0xFF})
		for _, p := range sortedPrefixes {
			_, _ = h.Write([]byte(p))
			_, _ = h.Write([]byte{0x00})
		}
	}
	_, _ = h.Write([]byte{0xFE})
	for _, a := range sortedAORs {
		_, _ = h.Write([]byte(a))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithAORs is the v1.10 Mutation that mixes
// method + INVITE prefix + REGISTER AOR allowlists into the
// PayloadHash. Degrades cleanly: empty aors → v1.9 behaviour;
// empty aors AND empty prefixes → v1.4 behaviour.
func SessionMutationWithAORs(target string, methods []AllowedMethod, prefixes []AllowedToURIPrefix, aors []AllowedAOR) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "sip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithAORs(target, methods, prefixes, aors),
	}
}

// canonicalisePrefix normalises a prefix string for hashing +
// compare: trim whitespace, strip any URI-scheme prefixes
// operators might accidentally include ("tel:", "sip:") and
// lowercase the result. Leading "+" is preserved because it's
// semantically meaningful for E.164 vs. bare-digit extension.
func canonicalisePrefix(p string) string {
	p = strings.TrimSpace(p)
	for _, scheme := range []string{"tel:", "sip:", "sips:"} {
		if strings.HasPrefix(strings.ToLower(p), scheme) {
			p = p[len(scheme):]
			break
		}
	}
	return strings.ToLower(p)
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
	// AllowedToURIPrefixes is the optional v1.9 INVITE destination
	// allowlist. When non-empty, an INVITE request passes only when
	// both (a) INVITE is in Allowed AND (b) the To: header's URI
	// user-part starts with one of these prefixes. Other gated
	// methods (REGISTER, MESSAGE, …) are NOT constrained by this
	// list; it only applies to INVITE (the toll-fraud vector).
	//
	// Empty list restores v1.4 behaviour (method-only gating).
	AllowedToURIPrefixes []AllowedToURIPrefix
	// AllowedAORs is the optional v1.10 REGISTER AOR allowlist.
	// When non-empty, a REGISTER request passes only when both
	// (a) REGISTER is in Allowed AND (b) the To: header's URI
	// (canonicalised user@host form) EXACTLY matches one of these
	// entries. The match is exact, not prefix (unlike
	// AllowedToURIPrefixes) — stolen creds for `alice@pbx`
	// shouldn't let an attacker register `admin@pbx`.
	//
	// Other gated methods (INVITE, MESSAGE, …) are NOT constrained
	// by this list. It gates REGISTER ONLY, which is the
	// registration-hijack vector.
	//
	// Empty list restores v1.9 behaviour (method + prefix gating
	// only; REGISTER passes as long as REGISTER is in Allowed).
	AllowedAORs []AllowedAOR
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
	m := SessionMutationWithAORs(h.Target, h.Allowed, h.AllowedToURIPrefixes, h.AllowedAORs)
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
		line, err := tp.ReadLine()
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		// Responses start with "SIP/" — client is misbehaving,
		// pass through so the upstream can decide.
		if strings.HasPrefix(line, "SIP/") {
			if err := passthroughRawHead(line, tp, upstream); err != nil {
				return err
			}
			continue
		}
		if err := h.forwardOne(line, br, tp, upstream, clientWriter); err != nil {
			return err
		}
	}
}

// forwardOne handles a single parsed request-line: reads its
// headers + body, applies the method + (optional) prefix gate,
// then forwards or refuses.
func (h *WriteGatedHandler) forwardOne(line string, br *bufio.Reader, tp *textproto.Reader, upstream, clientWriter io.Writer) error {
	method, ok := parseMethod(line)
	if !ok {
		return fmt.Errorf("sip: malformed request-line %q", truncate(line, 64))
	}
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
	if !h.allow(method) {
		return writeMethodNotAllowed(clientWriter, headers, h.allowedMethodsList())
	}
	if strings.EqualFold(method, "INVITE") && len(h.AllowedToURIPrefixes) > 0 {
		if !h.inviteDestinationAllowed(headers.Get("To")) {
			return writeInviteForbidden(clientWriter, headers)
		}
	}
	if strings.EqualFold(method, "REGISTER") && len(h.AllowedAORs) > 0 {
		if !h.registerAORAllowed(headers.Get("To")) {
			return writeRegisterForbidden(clientWriter, headers)
		}
	}
	return writeRequest(upstream, line, headers, body)
}

// registerAORAllowed reports whether the To: header's canonical
// AOR matches any operator-supplied AOR in the allowlist.
// Empty or unparseable To: header → refuse (fail-closed when
// the gate is active).
func (h *WriteGatedHandler) registerAORAllowed(toHeader string) bool {
	candidate := canonicaliseAOR(extractToURIFull(toHeader))
	if candidate == "" {
		return false
	}
	for _, a := range h.AllowedAORs {
		want := canonicaliseAOR(a.AOR)
		if want == "" {
			continue
		}
		if candidate == want {
			return true
		}
	}
	return false
}

// extractToURIFull returns the full URI (user@host form) from a
// `To:` header value, stripping display-name quoting + angle
// brackets + URI parameters. Keeps the host part (unlike
// extractToURIUser which drops it) because AOR gating is
// identity-level, not prefix-level.
//
// Examples:
//
//	"Alice <sip:alice@pbx.internal>;tag=abc"  → "alice@pbx.internal"
//	"<sips:bob@example.com>"                  → "bob@example.com"
//	"sip:+34911234@gateway"                   → "+34911234@gateway"
//
// Returns empty string on unparseable input.
func extractToURIFull(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	// Strip display-name quoting + angle brackets.
	if i := strings.IndexByte(header, '<'); i >= 0 {
		j := strings.IndexByte(header[i+1:], '>')
		if j < 0 {
			return ""
		}
		header = header[i+1 : i+1+j]
	}
	// Strip the uri-parameters suffix (";tag=...", etc.).
	if i := strings.IndexByte(header, ';'); i >= 0 {
		header = header[:i]
	}
	// Scheme prefix.
	for _, scheme := range []string{"sips:", "sip:", "tel:"} {
		if strings.HasPrefix(strings.ToLower(header), scheme) {
			header = header[len(scheme):]
			break
		}
	}
	return strings.TrimSpace(header)
}

// writeRegisterForbidden emits a SIP/2.0 403 Forbidden back to
// the client for a REGISTER that hit the method allowlist but
// NOT the AOR allowlist. Includes X-Elsereno-Gate-Reason so
// the operator can trace which gate fired (useful when BOTH the
// prefix + AOR gates are active on the same session).
func writeRegisterForbidden(w io.Writer, reqHeaders textproto.MIMEHeader) error {
	var b strings.Builder
	b.WriteString("SIP/2.0 403 Forbidden\r\n")
	for _, k := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
		for _, v := range reqHeaders.Values(k) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("Server: ElSereno proxy (gated, offensive)\r\n")
	b.WriteString("X-Elsereno-Gate-Reason: AOR not in session allowlist (REGISTER hijack guard)\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// inviteDestinationAllowed reports whether the To: header's URI
// user-part matches any operator-supplied prefix. Empty or
// unparseable To: header → refuse (fail-closed when the gate is
// active).
func (h *WriteGatedHandler) inviteDestinationAllowed(toHeader string) bool {
	user := extractToURIUser(toHeader)
	if user == "" {
		return false
	}
	userLower := strings.ToLower(user)
	for _, p := range h.AllowedToURIPrefixes {
		prefix := canonicalisePrefix(p.Prefix)
		if prefix == "" {
			continue
		}
		if strings.HasPrefix(userLower, prefix) {
			return true
		}
	}
	return false
}

// extractToURIUser parses a `To:` header value and returns the
// URI user-part. Examples:
//
//	"Alice <sip:+34600123456@example.com>;tag=abc"   → "+34600123456"
//	"<sip:201@pbx.internal>"                         → "201"
//	"sip:+1555@gateway"                              → "+1555"
//	"tel:+44203123;phone-context=…"                  → "+44203123"
//
// Returns empty string when the header is missing, unparseable,
// or uses a URI scheme we don't recognise.
func extractToURIUser(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	// Strip display-name quoting + angle brackets.
	if i := strings.IndexByte(header, '<'); i >= 0 {
		j := strings.IndexByte(header[i+1:], '>')
		if j < 0 {
			return ""
		}
		header = header[i+1 : i+1+j]
	}
	// Strip the uri-parameters suffix (";tag=...", etc.).
	if i := strings.IndexByte(header, ';'); i >= 0 {
		header = header[:i]
	}
	// Scheme prefix.
	for _, scheme := range []string{"sip:", "sips:", "tel:"} {
		if strings.HasPrefix(strings.ToLower(header), scheme) {
			header = header[len(scheme):]
			break
		}
	}
	// Take the user-part (everything before the '@').
	if i := strings.IndexByte(header, '@'); i >= 0 {
		header = header[:i]
	}
	return strings.TrimSpace(header)
}

// writeInviteForbidden emits a SIP/2.0 403 Forbidden back to
// the client for an INVITE that hit the destination allowlist
// but NOT the prefix list. Includes X-Elsereno-Gate-Reason so
// the operator can trace which gate fired.
func writeInviteForbidden(w io.Writer, reqHeaders textproto.MIMEHeader) error {
	var b strings.Builder
	b.WriteString("SIP/2.0 403 Forbidden\r\n") //nolint:misspell // RFC 3261 §21.4 canonical spelling
	for _, k := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
		for _, v := range reqHeaders.Values(k) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("Server: ElSereno proxy (gated, offensive)\r\n")
	b.WriteString("X-Elsereno-Gate-Reason: INVITE destination not in To-URI prefix allowlist\r\n")
	b.WriteString("Content-Length: 0\r\n\r\n")
	_, err := io.WriteString(w, b.String())
	return err
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
