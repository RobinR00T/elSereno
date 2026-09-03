//go:build offensive

package modbus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedWrite scopes a single function-code + unit + address-range
// tuple the operator has authorised for the current proxy session.
// The proxy-level Authorize runs once with the SHA-256 of the
// canonicalised allowlist as the payload hash; frames match against
// the allowlist at wire-parse time without a per-frame token.
type AllowedWrite struct {
	// Unit is the Modbus unit identifier. 0 matches any unit.
	Unit uint8
	// FC is the function code the operator accepts. Only
	// CategoryWrite FCs make sense here (5/6/15/16/22/23).
	FC mbwire.FunctionCode
	// StartAddr / EndAddr are the inclusive address range. Both
	// zero matches any address.
	StartAddr, EndAddr uint16
}

// Matches reports whether a parsed frame falls inside this entry.
func (a AllowedWrite) Matches(f mbwire.Frame) bool {
	if a.Unit != 0 && a.Unit != f.MBAP.Unit {
		return false
	}
	if a.FC != 0 && a.FC != f.FunctionCode() {
		return false
	}
	if a.StartAddr == 0 && a.EndAddr == 0 {
		return true
	}
	start, end, ok := frameAddrRange(f)
	if !ok {
		return false
	}
	// Check BOTH ends of the range: a multi-register/coil write that
	// starts inside the allowed window can still run off the top.
	return start >= a.StartAddr && end <= a.EndAddr
}

// frameAddr extracts the starting address from a known write FC.
// Returns (0, false) for FCs where the address lives at a different
// offset or not at all.
func frameAddr(f mbwire.Frame) (uint16, bool) {
	if len(f.PDU) < 3 {
		return 0, false
	}
	switch f.FunctionCode() { //nolint:exhaustive // address lives only in write FCs; others deliberately return (0,false)
	case mbwire.FCWriteSingleCoil,
		mbwire.FCWriteSingleRegister,
		mbwire.FCWriteMultipleCoils,
		mbwire.FCWriteMultipleRegisters,
		mbwire.FCMaskWriteRegister,
		mbwire.FCReadWriteMultipleRegisters:
		return binary.BigEndian.Uint16(f.PDU[1:3]), true
	}
	return 0, false
}

// frameAddrRange extracts the inclusive [start, end] address range a
// write frame touches. Returns (_, _, false) for FCs where it cannot
// be determined. Multi-register/coil writes span start..start+qty-1,
// so the gate must check both ends, not just the start.
func frameAddrRange(f mbwire.Frame) (start, end uint16, ok bool) {
	switch f.FunctionCode() { //nolint:exhaustive // address lives only in write FCs
	case mbwire.FCWriteSingleCoil, mbwire.FCWriteSingleRegister, mbwire.FCMaskWriteRegister:
		if len(f.PDU) < 3 {
			return 0, 0, false
		}
		a := binary.BigEndian.Uint16(f.PDU[1:3])
		return a, a, true
	case mbwire.FCWriteMultipleCoils, mbwire.FCWriteMultipleRegisters:
		return spanFromQuantity(f.PDU, 1, 3)
	case mbwire.FCReadWriteMultipleRegisters:
		// The write half mutates: write-start at PDU[5:7], qty at [7:9].
		return spanFromQuantity(f.PDU, 5, 7)
	}
	return 0, 0, false
}

// spanFromQuantity reads a start address at pdu[aOff:aOff+2] and a
// quantity at pdu[qOff:qOff+2] and returns the inclusive range,
// rejecting a range that would wrap past the 16-bit address space.
func spanFromQuantity(pdu []byte, aOff, qOff int) (uint16, uint16, bool) {
	if len(pdu) < qOff+2 {
		return 0, 0, false
	}
	a := binary.BigEndian.Uint16(pdu[aOff : aOff+2])
	qty := binary.BigEndian.Uint16(pdu[qOff : qOff+2])
	if qty == 0 {
		return a, a, true
	}
	if uint32(a)+uint32(qty)-1 > 0xFFFF {
		return 0, 0, false
	}
	return a, a + qty - 1, true
}

// AllowlistHash returns the deterministic SHA-256 of the allowlist.
// Entries are sorted before hashing so the operator's dry-run token
// is stable regardless of input order.
func AllowlistHash(target string, allowed []AllowedWrite) [32]byte {
	sorted := append([]AllowedWrite(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Unit != sorted[j].Unit {
			return sorted[i].Unit < sorted[j].Unit
		}
		if sorted[i].FC != sorted[j].FC {
			return sorted[i].FC < sorted[j].FC
		}
		if sorted[i].StartAddr != sorted[j].StartAddr {
			return sorted[i].StartAddr < sorted[j].StartAddr
		}
		return sorted[i].EndAddr < sorted[j].EndAddr
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [6]byte
	for _, a := range sorted {
		buf[0] = a.Unit
		buf[1] = byte(a.FC)
		binary.BigEndian.PutUint16(buf[2:4], a.StartAddr)
		binary.BigEndian.PutUint16(buf[4:6], a.EndAddr)
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises the
// whole proxy session for target + allowlist.
func SessionMutation(target string, allowed []AllowedWrite) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "modbus",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// AllowlistHashWithGeneration is the v1.17 chunk-3 hash that
// adds the token-generation cookie on top of the v1.2 base
// hash. Backwards-compat ladder: generation == 0 → equals
// AllowlistHash. All v1.2 → v1.16-chunk-4 confirm-tokens
// remain valid for operators who don't bump the generation.
//
// Hash layout (when generation != 0):
//
//	AllowlistHash output || 0xFC || u32 generation (big-endian)
//
// Mirrors the BACnet / CWMP / SIP token-generation design.
func AllowlistHashWithGeneration(target string, allowed []AllowedWrite, generation uint32) [32]byte {
	if generation == 0 {
		return AllowlistHash(target, allowed)
	}
	// Recompute from scratch + add the generation block — keeps
	// the inner-block layout identical to AllowlistHash so
	// generation=0 / generation>0 hashes share the same lower
	// bytes verbatim (just with the extra trailer).
	sorted := append([]AllowedWrite(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Unit != sorted[j].Unit {
			return sorted[i].Unit < sorted[j].Unit
		}
		if sorted[i].FC != sorted[j].FC {
			return sorted[i].FC < sorted[j].FC
		}
		if sorted[i].StartAddr != sorted[j].StartAddr {
			return sorted[i].StartAddr < sorted[j].StartAddr
		}
		return sorted[i].EndAddr < sorted[j].EndAddr
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [6]byte
	for _, a := range sorted {
		buf[0] = a.Unit
		buf[1] = byte(a.FC)
		binary.BigEndian.PutUint16(buf[2:4], a.StartAddr)
		binary.BigEndian.PutUint16(buf[4:6], a.EndAddr)
		_, _ = h.Write(buf[:])
	}
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], generation)
	_, _ = h.Write([]byte{0xFC})
	_, _ = h.Write(u32[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithGeneration is the v1.17 chunk-3 Mutation,
// the new top of the Modbus allowlist hash ladder.
// generation == 0 → degrades to SessionMutation.
func SessionMutationWithGeneration(target string, allowed []AllowedWrite, generation uint32) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "modbus",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithGeneration(target, allowed, generation),
	}
}

// AllowlistHashWithDiag is the top of the Modbus allowlist hash ladder.
// It binds the FC 8 Diagnostics sub-function allowlist (the mutating
// sub-functions the operator explicitly authorised) into the session
// token, so an operator cannot mint a token for a narrow write
// allowlist and then widen the proxy with --diag-subfunction without
// re-authorising.
//
// Backwards-compat: an empty diag allowlist produces a digest
// byte-identical to AllowlistHashWithGeneration(target, allowed,
// generation). Every pre-existing confirm-token therefore stays valid;
// only operators who add a --diag-subfunction entry need a fresh token.
//
// Hash layout (only the trailers that apply are written):
//
//	target || 0x00 || sorted write entries
//	        [ || 0xFC || u32 generation   when generation != 0 ]
//	        [ || 0xD8 || sorted u16 diag  when len(diag) != 0   ]
func AllowlistHashWithDiag(target string, allowed []AllowedWrite, generation uint32, diag []mbwire.DiagSubFunction) [32]byte {
	if len(diag) == 0 {
		return AllowlistHashWithGeneration(target, allowed, generation)
	}
	sorted := append([]AllowedWrite(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Unit != sorted[j].Unit {
			return sorted[i].Unit < sorted[j].Unit
		}
		if sorted[i].FC != sorted[j].FC {
			return sorted[i].FC < sorted[j].FC
		}
		if sorted[i].StartAddr != sorted[j].StartAddr {
			return sorted[i].StartAddr < sorted[j].StartAddr
		}
		return sorted[i].EndAddr < sorted[j].EndAddr
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [6]byte
	for _, a := range sorted {
		buf[0] = a.Unit
		buf[1] = byte(a.FC)
		binary.BigEndian.PutUint16(buf[2:4], a.StartAddr)
		binary.BigEndian.PutUint16(buf[4:6], a.EndAddr)
		_, _ = h.Write(buf[:])
	}
	if generation != 0 {
		var u32 [4]byte
		binary.BigEndian.PutUint32(u32[:], generation)
		_, _ = h.Write([]byte{0xFC})
		_, _ = h.Write(u32[:])
	}
	// Diag trailer: sort + de-duplicate so token stability does not
	// depend on flag order or accidental repeats.
	ds := append([]mbwire.DiagSubFunction(nil), diag...)
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	_, _ = h.Write([]byte{0xD8})
	var u16 [2]byte
	var prev mbwire.DiagSubFunction
	for i, d := range ds {
		if i > 0 && d == prev {
			continue
		}
		binary.BigEndian.PutUint16(u16[:], uint16(d))
		_, _ = h.Write(u16[:])
		prev = d
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithDiag is the Mutation at the top of the ladder,
// binding both the token generation and the FC 8 diag allowlist.
// An empty diag allowlist degrades to SessionMutationWithGeneration.
func SessionMutationWithDiag(target string, allowed []AllowedWrite, generation uint32, diag []mbwire.DiagSubFunction) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "modbus",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithDiag(target, allowed, generation, diag),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// write-ban proxy. Construction requires triple-confirm authorised
// session context (Deriver, Auditor, and the session-level Confirm
// struct). The handler does NOT re-authorise per frame — it checks
// the frame against the authorised allowlist and refuses anything
// outside it.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the list of (unit, fc, address-range) tuples the
	// operator authorised at session open. Empty list forbids all
	// writes (equivalent to the default write-ban handler).
	Allowed []AllowedWrite
	// AllowedDiag lists the FC 8 (Diagnostics) mutating sub-functions
	// the operator authorised. Read/echo/counter sub-functions always
	// forward; a mutating sub-function (Restart 0x01, Change Delimiter
	// 0x03, Force Listen Only 0x04, Clear Counters 0x0A, Clear Overrun
	// 0x14) or any reserved value forwards ONLY when listed here. Empty
	// list refuses every mutating/unknown diagnostic (default-deny).
	AllowedDiag []mbwire.DiagSubFunction
	// TokenGeneration is the v1.17 chunk-3 token-generation
	// cookie. Operators bump this when editing the allow-file
	// to invalidate pre-existing confirm-tokens. Default 0
	// preserves the v1.2 hash for backwards-compat.
	TokenGeneration uint32
	// Deriver + Auditor drive the session-open Authorize call.
	Deriver confirm.KeyDeriver
	Auditor confirm.Auditor
	// SessionConfirm is the Confirm struct the CLI populates from
	// --accept-writes / --confirm-target / --confirm-token. Reused
	// across every frame of the session.
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every byte that crosses the gate is timestamped
	// + direction-tagged + persisted. Wrapping happens BEFORE the
	// frame parser reads from client, so wire-aware gating
	// (allowed-fc routing, refusals) is captured intact. Nil
	// disables recording — the gate behaves exactly as it did
	// pre-v1.30.
	Recorder *replay.Recorder

	// authorised flips true after the first successful Authorize
	// call. A failed session-open short-circuits every subsequent
	// frame.
	authorised bool
}

// Authorise opens the proxy session: Authorize runs once with the
// SessionMutation. Must be called before Handle. Returns the same
// error set as confirm.Authorize so the CLI can route.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithDiag(h.Target, h.Allowed, h.TokenGeneration, h.AllowedDiag)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("modbus: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
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

// forward reads one client frame at a time and routes per policy.
// Allowed writes forward; out-of-allowlist writes short-circuit to
// IllegalFunction (same refusal as the default build).
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		frame, err := mbwire.ReadFrame(client)
		if err != nil {
			return err
		}
		if !h.shouldForward(frame) {
			resp := exceptionResponse(frame, mbwire.ExIllegalFunction)
			if werr := mbwire.WriteFrame(clientWriter, resp); werr != nil {
				return werr
			}
			continue
		}
		if werr := mbwire.WriteFrame(upstream, frame); werr != nil {
			return werr
		}
	}
}

// shouldForward returns true when the frame is a legitimate read OR
// a write that matches an AllowedWrite entry.
func (h *WriteGatedHandler) shouldForward(f mbwire.Frame) bool {
	if f.IsExceptionFrame() {
		return false
	}
	cat := mbwire.Classify(f.FunctionCode())
	switch cat {
	case mbwire.CategoryRead:
		return true
	case mbwire.CategoryWrite:
		for _, a := range h.Allowed {
			if a.Matches(f) {
				return true
			}
		}
		return false
	case mbwire.CategoryMEI:
		// Only sub-code 14 (Read Device Identification) survives.
		return len(f.PDU) >= 2 && f.PDU[1] == 0x0E
	case mbwire.CategoryDiagnostic:
		// FC 8 straddles read/write. Read/echo/counter sub-functions
		// forward freely; mutating (Restart, Force Listen Only, Clear
		// Counters, ...) and any reserved/unknown sub-function forward
		// only when explicitly allowlisted. Default-deny.
		sub, ok := f.DiagSubFunction()
		if !ok {
			// Malformed FC 8 (no sub-function): refuse.
			return false
		}
		if mbwire.DiagIsReadOnly(sub) {
			return true
		}
		for _, d := range h.AllowedDiag {
			if d == sub {
				return true
			}
		}
		return false
	case mbwire.CategoryUnknown:
		// Same conservative posture as the default write-ban
		// handler: unknown FCs refuse.
		return false
	}
	return false
}

// exceptionResponse builds an IllegalFunction reply for req.
func exceptionResponse(req mbwire.Frame, code mbwire.ExceptionCode) mbwire.Frame {
	fc := uint8(req.FunctionCode()) | 0x80
	return mbwire.Frame{
		MBAP: mbwire.MBAP{
			TxID:     req.MBAP.TxID,
			Protocol: mbwire.ProtocolID,
			Unit:     req.MBAP.Unit,
		},
		PDU: []byte{fc, uint8(code)},
	}
}
