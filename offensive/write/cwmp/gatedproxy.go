//go:build offensive

// Package cwmp implements the offensive write-gate proxy for
// TR-069 / CWMP ACS ↔ CPE traffic.
//
// TR-069 is the ISP-standard remote-management protocol for
// Customer Premises Equipment (routers, ONTs, STBs, phones).
// An ACS (Auto-Configuration Server) sends SOAP RPCs to CPEs to
// read state, push config, upgrade firmware, reboot, and
// factory-reset — making the ACS-CPE link one of the most
// privileged channels in the ISP network. A compromised or
// misconfigured ACS can push firmware to millions of devices.
//
// This gate sits in-line between the ACS and the CPE (operator-
// controlled audit / fleet-wide change-window setup) and
// allowlists the SOAP RPC name at a per-session grain.
//
// Architecture mirrors offensive/write/sip + offensive/write/
// pbxhttp (the ADR-040 template): per-session Authorise on the
// SHA-256 of a sorted allowlist, per-request filtering at wire-
// parse time. The CWMP specifics:
//
//   - The default proxy (internal/protocols/cwmp) refuses every
//     client byte with `HTTP/1.1 403 Forbidden`. This handler
//     is the gated variant.
//   - Every CWMP RPC is an HTTP POST carrying a SOAP 1.1
//     envelope. The RPC name is the first element child of
//     <Envelope><Body>: e.g. `<cwmp:SetParameterValues>` → RPC
//     name "SetParameterValues".
//   - Read-only + protocol-flow RPCs (GetParameter{Names,Values,
//     Attributes}, GetRPCMethods, Inform/InformResponse,
//     TransferComplete) always pass — blocking these would
//     break the CPE registration cycle.
//   - Write-capable RPCs (SetParameter{Values,Attributes},
//     AddObject, DeleteObject, Reboot, Download, Upload,
//     FactoryReset, ScheduleInform, ScheduleDownload,
//     ChangeDUState, CancelTransfer) require the operator to
//     list each one explicitly.
//   - Non-POST (GET/HEAD/OPTIONS) requests pass unconditionally.
//     TR-069 proper is POST-only, but many ACS deployments
//     expose read-only status/health endpoints on the same
//     port; refusing them would create a false dependency on
//     the gate for benign traffic.
//   - Refusal path emits a CWMP SOAP Fault (TR-069 Annex A
//     FaultCode 9001 "Request denied") so ACS code parses the
//     rejection as a proper CWMP-layer error rather than a
//     transport glitch. Headers carry an
//     X-Elsereno-Gate-Reason for operator trace.
//
// Out of scope for v1.11 chunk 1:
//   - Per-parameter-path allowlist (e.g. allow SetParameterValues
//     only on InternetGatewayDevice.WANDevice.* nodes). That's
//     a v1.12+ refinement analogous to OPC UA per-NodeId.
//   - Firmware-URL allowlist for Download. Would require pinning
//     hashes / signed manifests; a v1.13+ design question.
//   - Full XML-DSig / transport-level TLS verification. TR-069
//     deployments vary wildly in their trust setup; this gate
//     trusts whatever the transport already did.
package cwmp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"local/elsereno/offensive/confirm"
)

// AllowedRPC is one CWMP SOAP RPC name the operator has
// authorised for this session. Names are case-sensitive per
// TR-069 §A.4 — "SetParameterValues" ≠ "setparametervalues";
// the canonicaliser trims whitespace + strips any namespace
// prefix ("cwmp:") but preserves case.
//
// Typical gated RPCs:
//
//	SetParameterValues, SetParameterAttributes,
//	AddObject, DeleteObject, Reboot, FactoryReset,
//	Download, Upload, ScheduleInform, ScheduleDownload,
//	ChangeDUState, CancelTransfer
//
// Read-only + protocol-flow RPCs (GetParameter*, GetRPCMethods,
// Inform, InformResponse, TransferComplete, Kicked) are in the
// always-safe set and never need listing.
type AllowedRPC struct {
	// Name is the RPC identifier as it appears in the SOAP
	// Body's first child element tag. Case-sensitive.
	Name string
}

// canonicaliseRPC normalises an operator-supplied RPC name for
// hashing + compare. Strips whitespace and any "cwmp:" /
// "cwmp-1-0:" / "cwmp-1-2:" namespace-prefix the operator might
// have copy-pasted from wire captures. Case is preserved because
// CWMP RPC names ARE case-sensitive (SetParameterValues ≠
// setparametervalues in the TR-069 data model).
func canonicaliseRPC(s string) string {
	s = strings.TrimSpace(s)
	// Strip any "prefix:" (e.g. "cwmp:SetParameterValues").
	// CWMP uses a handful of namespace prefixes; we strip
	// anything up to the first colon as long as it looks like
	// an XML-name-token. Empty strings fall through to the
	// "" return.
	if i := strings.IndexByte(s, ':'); i > 0 {
		prefix := s[:i]
		if isXMLName(prefix) {
			s = s[i+1:]
		}
	}
	return strings.TrimSpace(s)
}

// isXMLName returns true if s is a plausible XML NameStartChar
// followed by NameChar* (ASCII-only fast path — CWMP namespace
// prefixes are always ASCII).
func isXMLName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c == '_':
			// ok as start or continue
		case i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '.'):
			// ok as continue only
		default:
			return false
		}
	}
	return true
}

// AllowlistHash returns the deterministic SHA-256 of the RPC
// allowlist. RPCs are canonicalised (namespace prefix stripped,
// case preserved) and sorted before hashing so the operator's
// dry-run token is stable regardless of input order or prefix
// style.
//
// Layout:
//
//	target || 0x00 || RPC<NUL> × sorted_rpcs
func AllowlistHash(target string, allowed []AllowedRPC) [32]byte {
	sorted := make([]string, 0, len(allowed))
	for _, a := range allowed {
		if c := canonicaliseRPC(a.Name); c != "" {
			sorted = append(sorted, c)
		}
	}
	sort.Strings(sorted)
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, r := range sorted {
		_, _ = h.Write([]byte(r))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises
// the proxy session for target + RPC allowlist. Same shape as
// the sip / pbxhttp / modbus / opcua templates.
func SessionMutation(target string, allowed []AllowedRPC) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "cwmp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// alwaysSafeRPCs lists the CWMP RPC names that always pass,
// regardless of the operator's allowlist. Reads, protocol-flow,
// and CPE→ACS informational RPCs that are required for the CPE
// registration cycle + basic operator visibility.
//
// Blocking these would break CPE registration; they're excluded
// from the gate by design.
var alwaysSafeRPCs = map[string]struct{}{
	"GetRPCMethods":                  {},
	"GetParameterNames":              {},
	"GetParameterValues":             {},
	"GetParameterAttributes":         {},
	"GetParameterNamesResponse":      {},
	"GetParameterValuesResponse":     {},
	"GetParameterAttributesResponse": {},
	"Inform":                         {},
	"InformResponse":                 {},
	"TransferComplete":               {},
	"TransferCompleteResponse":       {},
	"AutonomousTransferComplete":     {},
	"Kicked":                         {},
	"KickedResponse":                 {},
	// "Fault" itself is also protocol flow — blocking it would
	// mean a faulty RPC can't be reported to the peer.
	"Fault": {},
}

// WriteGatedHandler is the offensive replacement for the default
// CWMP deny-all proxy. Construction requires triple-confirm
// authorised session context.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the list of write-capable CWMP RPCs the
	// operator authorised at session open. Empty list forbids
	// every write-capable RPC (reads + protocol-flow still
	// pass via alwaysSafeRPCs).
	Allowed []AllowedRPC
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
var ErrSessionNotAuthorised = errors.New("cwmp: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. Parses HTTP requests from
// the client; for POST requests, extracts the SOAP RPC name and
// applies the gate. Non-POST requests pass unconditionally.
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
			return fmt.Errorf("cwmp: read request: %w", err)
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

// handleOne processes a single parsed HTTP request. Returns
// (done, err) where done=true signals the caller to stop the
// loop (Connection: close, context cancellation, etc.).
func (h *WriteGatedHandler) handleOne(ctx context.Context, req *http.Request, client, upstream io.Writer, upReader *bufio.Reader) (bool, error) {
	// Non-POST (GET/HEAD/OPTIONS/PROPFIND/...) bypasses the SOAP
	// gate — TR-069 RPCs are POST-only by spec; any other method
	// is either a vendor-specific status endpoint or health
	// probe, which shouldn't become a hard dependency on the
	// gate.
	if req.Method != http.MethodPost {
		return h.forwardRequest(req, client, upstream, upReader)
	}

	// Buffer the body so we can BOTH inspect it AND replay it
	// to upstream if the RPC passes.
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return false, fmt.Errorf("cwmp: read request body: %w", err)
	}
	rpc, ok := extractRPCName(body)
	if !ok || rpc == "" {
		// Not a parseable SOAP envelope — could be a heartbeat
		// or keep-alive POST with an empty body. Forward
		// transparently; the upstream ACS will return its own
		// error if the request is malformed.
		return h.forwardBuffered(req, body, client, upstream, upReader)
	}

	if _, safe := alwaysSafeRPCs[rpc]; safe {
		return h.forwardBuffered(req, body, client, upstream, upReader)
	}

	if !h.allow(rpc) {
		if werr := writeSOAPFault(client, rpc); werr != nil {
			return true, werr
		}
		// Gate refusal: don't forward. Keep the TCP stream open
		// for the next request unless the client asked for
		// close.
		if req.Close {
			return true, nil
		}
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		return false, nil
	}

	return h.forwardBuffered(req, body, client, upstream, upReader)
}

// allow returns true if the RPC is in the operator's allowlist.
// Canonicalised comparison (prefix stripped, whitespace trimmed;
// case preserved because CWMP RPC names are case-sensitive).
func (h *WriteGatedHandler) allow(rpc string) bool {
	rpc = canonicaliseRPC(rpc)
	if rpc == "" {
		return false
	}
	for _, a := range h.Allowed {
		if canonicaliseRPC(a.Name) == rpc {
			return true
		}
	}
	return false
}

// forwardRequest forwards a pristine *http.Request (no body
// rewrap) to upstream and relays the response to client. Used
// for non-POST requests where we don't need to inspect the body.
func (h *WriteGatedHandler) forwardRequest(req *http.Request, client, upstream io.Writer, upReader *bufio.Reader) (bool, error) {
	if err := req.Write(upstream); err != nil {
		return true, fmt.Errorf("cwmp: forward request: %w", err)
	}
	resp, err := http.ReadResponse(upReader, req)
	if err != nil {
		return true, fmt.Errorf("cwmp: read upstream response: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := resp.Write(client); err != nil {
		return true, fmt.Errorf("cwmp: forward response: %w", err)
	}
	if req.Close || resp.Close {
		return true, nil
	}
	return false, nil
}

// forwardBuffered forwards a POST whose body we already consumed
// into a []byte. Rewrites req.Body from the buffer + adjusts
// ContentLength before serialising via req.Write.
func (h *WriteGatedHandler) forwardBuffered(req *http.Request, body []byte, client, upstream io.Writer, upReader *bufio.Reader) (bool, error) {
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	req.ContentLength = int64(len(body))
	return h.forwardRequest(req, client, upstream, upReader)
}

// extractRPCName parses the SOAP envelope in the request body
// and returns the local name of the first element child of
// <Body>. Returns (name, true) on success, ("", false) when the
// body isn't parseable SOAP or the Body is empty.
//
// Implementation uses encoding/xml's streaming decoder so we
// don't materialise the whole parameter tree — only enough to
// find the RPC name. Robust against whitespace, XML comments,
// processing instructions, and the usual SOAP namespace
// variations (soap, soap-env, soapenv).
func extractRPCName(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	inBody := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !inBody {
			if strings.EqualFold(se.Name.Local, "Body") {
				inBody = true
			}
			continue
		}
		// First StartElement after <Body> is the RPC.
		return se.Name.Local, true
	}
}

// CWMP SOAP Fault codes per TR-069 Annex A. We only need the
// "request denied" code for gate refusals; other codes are the
// ACS's / CPE's concern.
const (
	cwmpFaultRequestDenied = "9001"
)

// writeSOAPFault emits an HTTP 200 OK carrying a CWMP SOAP
// Fault body (TR-069 treats per-RPC errors as application-
// level SOAP Faults, not HTTP errors — the transport always
// succeeds). The fault code 9001 "Request denied" maps cleanly
// to "gate refused this RPC". An X-Elsereno-Gate-Reason header
// adds operator trace.
func writeSOAPFault(w io.Writer, rpc string) error {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soap-env:Header>
    <cwmp:ID soap-env:mustUnderstand="1">elsereno-gate-refusal</cwmp:ID>
  </soap-env:Header>
  <soap-env:Body>
    <soap-env:Fault>
      <faultcode>Client</faultcode>
      <faultstring>CWMP fault</faultstring>
      <detail>
        <cwmp:Fault>
          <FaultCode>%s</FaultCode>
          <FaultString>RPC %q not in session allowlist (ElSereno gated proxy)</FaultString>
        </cwmp:Fault>
      </detail>
    </soap-env:Fault>
  </soap-env:Body>
</soap-env:Envelope>`, cwmpFaultRequestDenied, rpc)

	header := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Server: ElSereno proxy (gated, offensive)\r\n"+
			"Content-Type: text/xml; charset=utf-8\r\n"+
			"X-Elsereno-Gate-Reason: CWMP RPC %q not in session allowlist\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n",
		rpc, len(body),
	)
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	_, err := io.WriteString(w, body)
	return err
}
