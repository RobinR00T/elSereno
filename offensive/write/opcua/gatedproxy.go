//go:build offensive

// Package opcua implements the offensive write-gate proxy for
// OPC UA TCP (Part 6 §7.1 transport + Part 4 service framing).
//
// Architecture mirrors offensive/write/modbus (the ADR-040
// template): per-session Authorise on the SHA-256 of a sorted
// allowlist, per-frame filtering at wire-parse time. The UA
// specifics:
//
//   - Every client-to-server chunk is either HEL, OPN, MSG, or
//     CLO. HEL is the transport Hello (passes unchanged). OPN
//     opens a SecureChannel (passes unchanged; the gate is
//     higher-layer). CLO closes the channel (passes unchanged).
//     MSG carries service requests — that's where the gate acts.
//   - A MSG body begins with SecureChannelId + TokenId +
//     SequenceNumber + RequestId + ExpandedNodeId(TypeId). The
//     TypeId tells us WriteRequest (673) vs. CallRequest (704)
//     vs. ReadRequest / BrowseRequest / etc. Reads always pass;
//     writes + calls only pass when the service is in the
//     allowlist.
//   - Refusal path is a UA-native ServiceFault: same MSG chunk
//     framing, service TypeId 397 (ServiceFault), status
//     0x80100000 (BadUserAccessDenied). Real clients get a
//     parseable UA error rather than a TCP RST.
//
// Out of scope for v1.2 chunk 2: per-NodeId allowlisting (the
// TypeId alone is the gate). Full WriteValue / CallMethodRequest
// parsing to scope writes to specific nodes ships with v1.3
// alongside the UA binary-encoding parser.
package opcua

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
)

// AllowedService names one UA service the operator has
// authorised for the session. A literal BrowseRequest or
// ReadRequest entry is redundant — reads always pass — so the
// useful values here are TypeIDWriteRequest + TypeIDCallRequest.
// An empty allowlist is a "no writes" session, equivalent to
// the default deny-all proxy.
type AllowedService struct {
	// TypeID is a UA service request identifier (see
	// internal/protocols/opcua/wire TypeID*).
	TypeID uint16
}

// AllowlistHash returns the deterministic SHA-256 of the
// allowlist. Entries are sorted numerically before hashing so
// the operator's dry-run token is stable regardless of input
// order.
func AllowlistHash(target string, allowed []AllowedService) [32]byte {
	sorted := append([]AllowedService(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TypeID < sorted[j].TypeID
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [2]byte
	for _, a := range sorted {
		binary.BigEndian.PutUint16(buf[:], a.TypeID)
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises
// the proxy session for target + allowlist. Same shape as the
// modbus / s7 / enip templates so the CLI wiring stays uniform.
func SessionMutation(target string, allowed []AllowedService) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcua",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// UA deny-all proxy. Construction requires triple-confirm
// authorised session context (Deriver, Auditor, and the
// session-level Confirm struct). The handler does NOT
// re-authorise per frame — it parses the UA-TCP framing and
// allows (a) HEL/OPN/CLO always, (b) MSG with TypeId in the
// allowlist OR any non-mutating service TypeId.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the list of service TypeIds the operator
	// authorised at session open. Empty list forbids every
	// mutating service (equivalent to the default deny-all
	// handler for writes; reads still pass).
	Allowed []AllowedService
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
// Handle. Returns the same error set as confirm.Authorize so
// the CLI can route.
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
var ErrSessionNotAuthorised = errors.New("opcua: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler.
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
		return err
	}
}

// forward reads one UA-TCP frame at a time from the client and
// routes per policy. HEL/OPN/CLO pass unchanged; MSG is
// inspected and either forwarded or replaced with a
// ServiceFault.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	hdr := make([]byte, wire.HeaderSize)
	for {
		if _, err := io.ReadFull(client, hdr); err != nil {
			return err
		}
		header, err := wire.ParseHeader(hdr)
		if err != nil {
			return fmt.Errorf("opcua: parse header: %w", err)
		}
		bodyLen := int(header.Length) - wire.HeaderSize
		if bodyLen < 0 {
			return fmt.Errorf("opcua: negative body length %d", bodyLen)
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(client, body); err != nil {
				return err
			}
		}
		if err := h.routeFrame(header, body, upstream, clientWriter); err != nil {
			return err
		}
	}
}

// routeFrame is the per-frame policy decision.
func (h *WriteGatedHandler) routeFrame(header wire.Header, body []byte, upstream, clientWriter io.Writer) error {
	// HEL/OPN/CLO: transport-level frames. Always forward.
	// The gate only cares about service requests, which live
	// inside MSG chunks. An OPN that fails later on the server
	// side will surface as a server-emitted ERR on the return
	// path — we don't need to second-guess here.
	if header.Type != wire.MessageMessage {
		return writeFrame(upstream, header.Type, body)
	}
	typeID, ok := wire.ServiceTypeID(body)
	if !ok {
		// Unknown TypeId encoding → forward. We want to stay
		// conservative about refusing traffic we can't read;
		// refusing would break vendor clients that use
		// encodings outside TwoByte/FourByte for service
		// requests (none do in practice, but the safer default
		// is "forward unknown, refuse known-mutating").
		return writeFrame(upstream, header.Type, body)
	}
	if !wire.IsMutatingService(typeID) {
		return writeFrame(upstream, header.Type, body)
	}
	if h.isAllowed(typeID) {
		return writeFrame(upstream, header.Type, body)
	}
	// Refuse: emit a UA ServiceFault back to the client.
	return writeServiceFault(clientWriter, body)
}

// isAllowed reports whether the given service TypeId is in the
// session's allowlist.
func (h *WriteGatedHandler) isAllowed(typeID uint16) bool {
	for _, a := range h.Allowed {
		if a.TypeID == typeID {
			return true
		}
	}
	return false
}

// writeFrame emits a UA-TCP chunk with the given type + body.
// Manually wrapped so we don't depend on the wire package's
// internal `wrap` helper (which is private). The chunk is
// always final ('F') because the handler doesn't split service
// requests — if the client sent a continuation chunk, we
// forward it byte-for-byte already (body copy above).
func writeFrame(w io.Writer, mt wire.MessageType, body []byte) error {
	frame := make([]byte, wire.HeaderSize+len(body))
	copy(frame[0:3], string(mt))
	frame[3] = byte(wire.ChunkFinal)
	// #nosec G115 — header+body ≤ MaxMessageSize (1 MiB) by construction
	binary.LittleEndian.PutUint32(frame[4:8], uint32(wire.HeaderSize+len(body)))
	copy(frame[wire.HeaderSize:], body)
	_, err := w.Write(frame)
	return err
}

// Bad_UserAccessDenied status code (Part 4 Annex A). The upper
// 16 bits are the StatusCode severity+subcode; the lower 16 are
// informational.
const statusBadUserAccessDenied uint32 = 0x80100000

// ServiceFault TypeId — OPC-UA Part 4 §5.5.2.
const typeIDServiceFault uint16 = 397

// writeServiceFault emits a minimal UA ServiceFault MSG in
// response to a blocked request. Body layout:
//
//	[0..3]   SecureChannelId  — copied from the blocked request
//	[4..7]   TokenId          — copied
//	[8..11]  SequenceNumber   — +1 from the blocked request
//	[12..15] RequestId        — copied (binds reply → request)
//	[16..]   ExpandedNodeId   — FourByteNodeId, ns=0, id=397 (ServiceFault)
//	[...]    ResponseHeader   — Timestamp(now)=0 + RequestHandle(0) +
//	                            ServiceResult=BadUserAccessDenied +
//	                            ServiceDiagnostics(null) +
//	                            StringTable(empty) +
//	                            AdditionalHeader(null extension)
//
// Timestamps encoded as Windows-FILETIME ticks are zeroed
// because the gate does not need an accurate server clock and
// some minimal UA clients reject future timestamps > a few
// minutes drift. The response header wire layout here is
// deliberately minimal-but-valid per Part 6 §5.2.
func writeServiceFault(w io.Writer, blockedBody []byte) error {
	if len(blockedBody) < 16 {
		return fmt.Errorf("opcua: blocked body too short to mirror headers (%d)", len(blockedBody))
	}
	// Build response body.
	body := make([]byte, 0, 64)
	// Mirror SecureChannelId / TokenId / SequenceNumber + 1 / RequestId.
	body = append(body, blockedBody[0:4]...)
	body = append(body, blockedBody[4:8]...)
	seq := binary.LittleEndian.Uint32(blockedBody[8:12]) + 1
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], seq)
	body = append(body, u32[:]...)
	body = append(body, blockedBody[12:16]...)
	// ExpandedNodeId: FourByteNodeId ns=0 id=397.
	body = append(body,
		byte(wire.NodeIDFourByte), // encoding
		0x00,                      // namespace
	)
	binary.LittleEndian.PutUint32(u32[:], 0) // temp reset
	var tid [2]byte
	binary.LittleEndian.PutUint16(tid[:], typeIDServiceFault)
	body = append(body, tid[:]...)
	// ResponseHeader:
	//   Timestamp (UtcTime = i64): 0
	body = append(body, make([]byte, 8)...)
	//   RequestHandle (u32): 0
	body = append(body, make([]byte, 4)...)
	//   ServiceResult (StatusCode u32 LE): BadUserAccessDenied
	binary.LittleEndian.PutUint32(u32[:], statusBadUserAccessDenied)
	body = append(body, u32[:]...)
	//   ServiceDiagnostics (DiagnosticInfo): encoding mask = 0x00 (nothing)
	body = append(body, 0x00)
	//   StringTable (i32 length prefix): -1 (null array)
	body = append(body, 0xFF, 0xFF, 0xFF, 0xFF)
	//   AdditionalHeader (ExtensionObject):
	//     TypeId NodeId: TwoByteNodeId id=0 (null)
	body = append(body, byte(wire.NodeIDTwoByte), 0x00)
	//     EncodingMask: 0x00 (no body)
	body = append(body, 0x00)
	return writeFrame(w, wire.MessageMessage, body)
}
