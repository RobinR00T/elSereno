//go:build offensive

// Package opcuahttps implements the offensive write-gate proxy for the
// OPC UA HTTPS binary binding (Part 6 §7.4).
//
// Architecture mirrors offensive/write/pbxhttp (an HTTP gate over the
// raw stream via net/http's server-side parser) crossed with
// offensive/write/opcua (the UA service + NodeId + CallMethod
// allowlist). The specifics:
//
//   - The HTTPS binding carries each UA service request as an HTTP POST
//     body: a *bare* UA-Binary message (TypeId at offset 0, no opc.tcp
//     SecureChannel framing). The gate reads the body, classifies the
//     service via wire.ServiceTypeIDHTTPS, and decides.
//   - Read-only / non-mutating services (Read, Browse, GetEndpoints,
//     CreateSession, ...) always pass. Only WriteRequest (673) and
//     CallRequest (704) are gated, against the same allowlist
//     dimensions the opcua TCP gate uses: service TypeID, numeric +
//     canonical NodeID (for WriteRequest), and (Object, Method) pairs
//     (for CallRequest). The allowlist types are reused verbatim from
//     offensive/write/opcua so an operator writes one allowlist shape
//     for both transports.
//   - Non-POST methods (GET / HEAD / OPTIONS) pass unchanged: they do
//     not carry UA service requests, and operators need them to reach a
//     server's HTTP surface. A body the parser cannot classify is
//     forwarded (same conservative "forward unknown, refuse
//     known-mutating" stance the opcua TCP gate documents: service
//     TypeIds are always Two/FourByte numeric, so an unclassifiable
//     body is malformed, not a hidden write, and the upstream rejects
//     it).
//   - Refusal path is a UA-native ServiceFault (Part 4 §7.5.2) returned
//     as the HTTP 200 body with Content-Type application/octet-stream
//     and ServiceResult Bad_UserAccessDenied. A real UA client decodes
//     a parseable service error, exactly as the opcua TCP gate returns
//     a ServiceFault MSG rather than a TCP RST.
//
// TLS, like offensive/write/pbxhttp, is a deployment concern: the gate
// inspects the HTTP + UA-Binary application layer. Terminate TLS in
// front of the gate (or point it at a plaintext upstream); the gate
// does not man-in-the-middle a TLS session itself.
//
// The token is scoped to protocol "opcuahttps": a token minted for the
// opcua TCP gate does not authorise HTTPS writes, and vice versa, even
// for an identical allowlist. Different transport, different exposure.
package opcuahttps

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
	opcua "local/elsereno/offensive/write/opcua"
)

// SessionMutation builds the confirm.Mutation that authorises the proxy
// session for target + the full allowlist (service TypeIDs, numeric +
// canonical NodeIDs, CallMethods) and token generation. The PayloadHash
// reuses the opcua hash ladder so the allowlist encoding is identical
// across transports; the Protocol field ("opcuahttps") is what scopes
// the token to this binding.
func SessionMutation(
	target string,
	services []opcua.AllowedService,
	nodeIDs []opcua.AllowedNodeID,
	canonicalNodeIDs []opcua.AllowedCanonicalNodeID,
	callMethods []opcua.AllowedCallMethod,
	generation uint32,
) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcuahttps",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: opcua.AllowlistHashWithGeneration(target, services, nodeIDs, canonicalNodeIDs, callMethods, generation),
	}
}

// defaultMaxBody bounds the POST body the gate will buffer to classify
// and forward. UA operational writes are tiny (a setpoint); 1 MiB is
// the same ceiling wire.MaxMessageSize applies to opc.tcp frames.
const defaultMaxBody int64 = wire.MaxMessageSize

// WriteGatedHandler is the offensive replacement for the opcuahttps
// deny-all proxy. Construction requires triple-confirm authorised
// session context (Deriver, Auditor, and the session-level Confirm).
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the list of service TypeIds the operator authorised.
	// Empty forbids every mutating service (reads still pass).
	Allowed []opcua.AllowedService
	// AllowedNodeIDs is the optional per-node allowlist for numeric
	// NodeIDs on WriteRequest. See offensive/write/opcua.AllowedNodeID.
	AllowedNodeIDs []opcua.AllowedNodeID
	// AllowedCanonicalNodeIDs is the optional per-node allowlist for
	// String / Guid / ByteString (and numeric-in-canonical-form)
	// NodeIDs on WriteRequest. When either NodeID list is non-empty the
	// gate walks EVERY WriteValue and admits the frame only when every
	// NodeId matches its respective list.
	AllowedCanonicalNodeIDs []opcua.AllowedCanonicalNodeID
	// AllowedCallMethods is the optional per-CallMethod allowlist. When
	// non-empty, a CallRequest is forwarded only when EVERY
	// (ObjectID, MethodID) pair matches one of these entries.
	AllowedCallMethods []opcua.AllowedCallMethod
	// TokenGeneration is the rotation cookie. Default 0 keeps the base
	// hash.
	TokenGeneration uint32
	// Deriver + Auditor drive the session-open Authorize call.
	Deriver confirm.KeyDeriver
	Auditor confirm.Auditor
	// SessionConfirm is the Confirm struct the CLI populates from
	// --accept-writes / --confirm-target / --confirm-token.
	SessionConfirm confirm.Confirm
	// Recorder optionally captures the proxy session to NDJSON. When
	// non-nil, Handle wraps both io.ReadWriters before the HTTP parser
	// so every request + response that crosses the gate is persisted.
	Recorder *replay.Recorder
	// MaxBodyBytes overrides defaultMaxBody when > 0. Bodies larger than
	// the cap are refused (they cannot be classified or safely
	// buffered for forwarding).
	MaxBodyBytes int64

	// authorised flips true after a successful Authorise.
	authorised bool
}

func (h *WriteGatedHandler) maxBody() int64 {
	if h.MaxBodyBytes > 0 {
		return h.MaxBodyBytes
	}
	return defaultMaxBody
}

// Authorise opens the proxy session. Must be called before Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed, h.AllowedNodeIDs, h.AllowedCanonicalNodeIDs, h.AllowedCallMethods, h.TokenGeneration)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise has not
// been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("opcuahttps: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler. Parses requests from the client
// with net/http's server-side parser, applies the gate, and forwards
// allowed requests to upstream while returning the upstream response to
// the client.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
	}
	br := bufio.NewReader(client)
	upReader := bufio.NewReader(upstream)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("opcuahttps: read request: %w", err)
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

// handleOne processes a single parsed request. Returns (done, err)
// where done=true stops the loop (Connection: close, oversize body,
// context cancellation, ...).
func (h *WriteGatedHandler) handleOne(ctx context.Context, req *http.Request, client, upstream io.Writer, upReader *bufio.Reader) (bool, error) {
	// CONNECT tunnels traffic the gate cannot inspect: always refuse.
	if req.Method == http.MethodConnect {
		return true, writeServiceFaultHTTP(client, "CONNECT tunnelling is not supported by the gated proxy", true)
	}

	body, tooBig, err := readBody(req, h.maxBody())
	if err != nil {
		return true, fmt.Errorf("opcuahttps: read body: %w", err)
	}
	if tooBig {
		// Cannot classify or safely re-buffer an oversize body.
		return true, writeServiceFaultHTTP(client, "request body exceeds the gate's size limit", true)
	}

	pass, reason := h.gate(req, body)
	if !pass {
		if wErr := writeServiceFaultHTTP(client, reason, false); wErr != nil {
			return true, wErr
		}
		// Refusal keeps the connection open for the next request.
		if req.Close {
			return true, nil
		}
		return false, nil
	}

	return h.forward(ctx, req, body, client, upstream, upReader)
}

// forward re-attaches the buffered body and relays the request to
// upstream, then copies the upstream response back to the client.
func (h *WriteGatedHandler) forward(ctx context.Context, req *http.Request, body []byte, client, upstream io.Writer, upReader *bufio.Reader) (bool, error) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.TransferEncoding = nil // force Content-Length framing on re-emit
	if err := req.Write(upstream); err != nil {
		return true, fmt.Errorf("opcuahttps: forward request: %w", err)
	}
	resp, err := http.ReadResponse(upReader, req)
	if err != nil {
		return true, fmt.Errorf("opcuahttps: read upstream response: %w", err)
	}
	writeErr := resp.Write(client)
	_ = resp.Body.Close()
	if writeErr != nil {
		return true, fmt.Errorf("opcuahttps: forward response: %w", writeErr)
	}
	if req.Close || resp.Close {
		return true, nil
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	return false, nil
}

// gate makes the per-request policy decision. Returns (true, "") to
// forward, (false, reason) to refuse.
func (h *WriteGatedHandler) gate(req *http.Request, body []byte) (bool, string) {
	// UA service requests ride on POST. Everything else (GET/HEAD/
	// OPTIONS/...) carries no service call: forward.
	if req.Method != http.MethodPost {
		return true, ""
	}
	typeID, ok := wire.ServiceTypeIDHTTPS(body)
	if !ok {
		// Not a classifiable service message. Forward (upstream
		// validates); service TypeIds are always Two/FourByte numeric.
		return true, ""
	}
	if !wire.IsMutatingService(typeID) {
		return true, "" // Read / Browse / GetEndpoints / session mgmt.
	}
	if !h.isServiceAllowed(typeID) {
		return false, fmt.Sprintf("service TypeId %d is not in the session allowlist", typeID)
	}
	if typeID == wire.TypeIDWriteRequest && h.perNodeGateActive() {
		if !h.writeRequestNodesAllowed(body) {
			return false, "WriteRequest targets a NodeId outside the session allowlist"
		}
	}
	if typeID == wire.TypeIDCallRequest && len(h.AllowedCallMethods) > 0 {
		if !h.callRequestMethodsAllowed(body) {
			return false, "CallRequest targets a method outside the session allowlist"
		}
	}
	return true, ""
}

// isServiceAllowed reports whether the given service TypeId is in the
// session's allowlist.
func (h *WriteGatedHandler) isServiceAllowed(typeID uint16) bool {
	for _, a := range h.Allowed {
		if a.TypeID == typeID {
			return true
		}
	}
	return false
}

// perNodeGateActive reports whether EITHER per-NodeId allowlist is
// populated.
func (h *WriteGatedHandler) perNodeGateActive() bool {
	return len(h.AllowedNodeIDs) > 0 || len(h.AllowedCanonicalNodeIDs) > 0
}

// writeRequestNodesAllowed reports whether the bare WriteRequest body
// targets ONLY NodeIds in the operator's allowlists. Fail-closed: an
// unparseable NodesToWrite array refuses the whole request.
func (h *WriteGatedHandler) writeRequestNodesAllowed(body []byte) bool {
	nodes, ok := wire.WriteRequestAllNodesRichHTTPS(body)
	if !ok || len(nodes) == 0 {
		return false
	}
	for _, nid := range nodes {
		if !h.richNodeIDAllowed(nid) {
			return false
		}
	}
	return true
}

// richNodeIDAllowed reports whether one parsed NodeId matches either
// the numeric allowlist (numeric encodings only) or the canonical
// allowlist (any encoding). Mirrors offensive/write/opcua's
// richNodeIDAllowed.
func (h *WriteGatedHandler) richNodeIDAllowed(nid wire.NodeIDValue) bool {
	if nid.Kind == wire.NodeIDKindNumeric {
		for _, a := range h.AllowedNodeIDs {
			if a.Namespace == nid.Namespace && a.Identifier == nid.Numeric {
				return true
			}
		}
	}
	canon := nid.Canonical()
	if canon == "" {
		return false
	}
	for _, c := range h.AllowedCanonicalNodeIDs {
		if string(c) == canon {
			return true
		}
	}
	return false
}

// callRequestMethodsAllowed reports whether the bare CallRequest body
// targets ONLY (ObjectID, MethodID) pairs in the allowlist. Fail-closed
// on an unparseable MethodsToCall array.
func (h *WriteGatedHandler) callRequestMethodsAllowed(body []byte) bool {
	methods, ok := wire.CallRequestAllMethodsHTTPS(body)
	if !ok || len(methods) == 0 {
		return false
	}
	for _, cm := range methods {
		if !h.callMethodInAllowlist(cm) {
			return false
		}
	}
	return true
}

// callMethodInAllowlist reports whether one (Object, Method) pair
// matches any AllowedCallMethod entry, compared on canonical-string
// form.
func (h *WriteGatedHandler) callMethodInAllowlist(cm wire.CallMethod) bool {
	obj := cm.ObjectID.Canonical()
	mth := cm.MethodID.Canonical()
	if obj == "" || mth == "" {
		return false
	}
	for _, a := range h.AllowedCallMethods {
		if a.ObjectID == obj && a.MethodID == mth {
			return true
		}
	}
	return false
}

// readBody drains the request body up to max bytes. Returns
// (body, tooBig, err): tooBig is true when the body exceeds max (the
// caller refuses). The request body is always closed.
func readBody(req *http.Request, max int64) (body []byte, tooBig bool, err error) {
	if req.Body == nil {
		return nil, false, nil
	}
	defer func() { _ = req.Body.Close() }()
	b, readErr := io.ReadAll(io.LimitReader(req.Body, max+1))
	if readErr != nil {
		return nil, false, readErr
	}
	if int64(len(b)) > max {
		return nil, true, nil
	}
	return b, false, nil
}

// writeServiceFaultHTTP emits an HTTP 200 response whose body is a
// bare UA ServiceFault (Bad_UserAccessDenied). reason is echoed in an
// observability header. close forces Connection: close.
func writeServiceFaultHTTP(w io.Writer, reason string, closeConn bool) error {
	fault := wire.EncodeServiceFaultHTTPS(wire.StatusBadUserAccessDenied)
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Server: ElSereno proxy (gated, offensive)\r\n")
	b.WriteString("Content-Type: application/octet-stream\r\n")
	if reason != "" {
		b.WriteString("X-Elsereno-Gate-Reason: ")
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(reason, "\r", " "), "\n", " "))
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(fault))
	if closeConn {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	_, err := w.Write(fault)
	return err
}
