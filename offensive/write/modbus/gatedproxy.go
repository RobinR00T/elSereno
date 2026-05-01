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
	addr, ok := frameAddr(f)
	if !ok {
		return false
	}
	return addr >= a.StartAddr && addr <= a.EndAddr
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
	m := SessionMutationWithGeneration(h.Target, h.Allowed, h.TokenGeneration)
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
		// Diagnostics is permissive in the default build; the
		// offensive proxy keeps the same posture — per-sub-code
		// gating tracked for F-future.
		return true
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
