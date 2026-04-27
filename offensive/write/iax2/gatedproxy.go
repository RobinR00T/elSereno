//go:build offensive

// Package iax2 implements the offensive write-gate proxy for
// Asterisk's native binary IAX2 protocol (RFC 5456) on UDP 4569.
//
// Architecture mirrors offensive/write/sip + offensive/write/pbxhttp
// (ADR-040 template): per-session Authorise on the SHA-256 of a
// sorted allowlist, per-datagram filtering at wire-parse time. The
// IAX2 specifics:
//
//   - The default proxy (internal/protocols/iax2) refuses every
//     client byte. This handler replaces that default only when
//     `-tags offensive` is built AND the three operator fences
//     pass.
//   - IAX2 is UDP: each datagram is independent. Each call to
//     client.Read returns one complete frame (caller is expected
//     to wire this handler with PacketConn semantics; net.Pipe in
//     tests gives the same per-Write → per-Read behaviour).
//   - Mini-frames (audio; byte[0] high bit = 0) ALWAYS pass. The
//     gate cannot reasonably inspect real-time audio; blocking a
//     mini-frame would break the call mid-stream in an audible
//     way and is never what the operator wants.
//   - Full-frame control messages are classified by FrameType +
//     Subclass. The gate always-passes:
//     FrameType != IAX (DTMF / Voice / Video / Text / Image /
//     HTML / CNG / Null — these are media or presentation,
//     never state-changing at the control layer).
//     IAX subclass in the always-safe set: HANGUP, ACK,
//     LAGRQ, LAGRP, INVAL, PING, PONG, REGAUTH, REGACK,
//     REGREJ, REGREL — call teardown, transaction ack,
//     latency measurement, registration server-side flow.
//   - Gated IAX subclasses (require operator allowlist):
//     NEW      — call setup. Toll fraud risk.
//     REGREQ   — registration. Binding hijack.
//     AUTHREP  — auth reply. Credential submission.
//     ACCEPT   — accept incoming call (rare from a client,
//     included for completeness).
//   - Refusal path: reply with a HANGUP full-frame addressed to
//     the client's source-call number. IAX2 has no standard
//     "permission denied" message, but HANGUP is the universal
//     call-teardown signal; real clients interpret it as "the
//     server dropped the call" and exit the dialogue cleanly.
//   - Response path (upstream→client) is a straight io.Copy. The
//     upstream can send anything back — AUTHREQ, ACCEPT, HANGUP,
//     audio mini-frames — and operators always want to see it.
//
// Out of scope for v1.4 chunk 3 (slated for v1.5+): IE-level
// allowlisting (e.g. allow NEW but only to specific
// CALLED_NUMBERs; allow REGREQ but only from specific USERNAMEs).
// Parsing the IE TLV stream + matching on specific values is the
// next tightening of the gate once the subclass-level filter has
// field hours.
package iax2

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"local/elsereno/internal/protocols/iax2/wire"
	"local/elsereno/offensive/confirm"
)

// AllowedSubclass is one IAX2 full-frame control subclass the
// operator has authorised for the session. Always-safe subclasses
// (HANGUP / ACK / PING / PONG / etc.) do not need to be listed.
type AllowedSubclass struct {
	// Subclass is a wire.IAXSubclass value (NEW, REGREQ,
	// AUTHREP, ACCEPT).
	Subclass wire.IAXSubclass
}

// AllowlistHash returns the deterministic SHA-256 of the
// allowlist. Subclasses are sorted numerically before hashing so
// the operator's dry-run token is stable regardless of input
// order.
func AllowlistHash(target string, allowed []AllowedSubclass) [32]byte {
	sorted := make([]uint8, 0, len(allowed))
	for _, a := range allowed {
		sorted = append(sorted, uint8(a.Subclass))
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, s := range sorted {
		_, _ = h.Write([]byte{s})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises the
// proxy session.
func SessionMutation(target string, allowed []AllowedSubclass) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "iax2",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// AllowlistHashWithGeneration is the v1.17 chunk-3 hash that
// adds the token-generation cookie. generation == 0 → equals
// AllowlistHash. Mirrors the BACnet/CWMP/SIP/Modbus design.
func AllowlistHashWithGeneration(target string, allowed []AllowedSubclass, generation uint32) [32]byte {
	if generation == 0 {
		return AllowlistHash(target, allowed)
	}
	sorted := make([]uint8, 0, len(allowed))
	for _, a := range allowed {
		sorted = append(sorted, uint8(a.Subclass))
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, s := range sorted {
		_, _ = h.Write([]byte{s})
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
// the new top of the IAX2 hash ladder.
func SessionMutationWithGeneration(target string, allowed []AllowedSubclass, generation uint32) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "iax2",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithGeneration(target, allowed, generation),
	}
}

// alwaysSafeIAXSubclasses: IAX control messages that always pass,
// regardless of the operator's allowlist.
var alwaysSafeIAXSubclasses = map[wire.IAXSubclass]struct{}{
	wire.IAXAck:     {},
	wire.IAXHangup:  {},
	wire.IAXPing:    {},
	wire.IAXPong:    {},
	wire.IAXLagRq:   {},
	wire.IAXLagRp:   {},
	wire.IAXInval:   {},
	wire.IAXRegauth: {},
	wire.IAXRegack:  {},
	wire.IAXRegrej:  {},
	wire.IAXRegrel:  {},
	// REJECT is a server-side refusal but can be sent by
	// middle-boxes; pass it through.
	wire.IAXReject: {},
}

// WriteGatedHandler is the offensive replacement for the default
// IAX2 deny-all proxy.
type WriteGatedHandler struct {
	Target  string
	Allowed []AllowedSubclass
	// TokenGeneration is the v1.17 chunk-3 cookie. Default 0
	// preserves the v1.5 hash for backwards-compat.
	TokenGeneration uint32
	Deriver         confirm.KeyDeriver
	Auditor         confirm.Auditor
	SessionConfirm  confirm.Confirm

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
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
var ErrSessionNotAuthorised = errors.New("iax2: write-gated proxy requires Authorise() first")

// maxDatagramSize caps a single IAX2 read at 4 KiB. Real-world
// IAX2 frames are well under 1500 bytes (Ethernet MTU); 4 KiB
// gives slack for IE-heavy full frames without letting a
// compromised client starve the proxy.
const maxDatagramSize = 4096

// Handle implements core.ProxyHandler. Splits into two goroutines:
// client→upstream is parsed + gated per datagram; upstream→client
// is a straight io.Copy (responses never gated).
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

// forward reads datagrams from the client and routes per policy.
// One Read = one IAX2 frame (UDP semantics).
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	buf := make([]byte, maxDatagramSize)
	for {
		n, readErr := client.Read(buf)
		if n > 0 {
			if err := h.routeFrame(buf[:n], upstream, clientWriter); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

// routeFrame decides what to do with one datagram.
func (h *WriteGatedHandler) routeFrame(frame []byte, upstream, clientWriter io.Writer) error {
	// Frames under HeaderLen can't be full frames; pass them
	// (could be malformed or a short mini-frame).
	if len(frame) < wire.HeaderLen {
		_, err := upstream.Write(frame)
		return err
	}
	header, err := wire.ParseHeader(frame)
	if err != nil {
		// Mini-frame (ErrMiniFrame) or too-short → always
		// forward. We explicitly don't gate audio.
		_, werr := upstream.Write(frame)
		return werr
	}
	// Non-IAX control frame (DTMF/Voice/Video/Text/…) → always
	// forward.
	if header.FrameType != wire.FrameTypeIAX {
		_, werr := upstream.Write(frame)
		return werr
	}
	sub := wire.IAXSubclass(header.Subclass)
	if _, safe := alwaysSafeIAXSubclasses[sub]; safe {
		_, werr := upstream.Write(frame)
		return werr
	}
	if h.isAllowed(sub) {
		_, werr := upstream.Write(frame)
		return werr
	}
	// Refuse: reply with a HANGUP addressed to the client's
	// SrcCallNum. Drops the call cleanly from the client's POV
	// without forwarding anything to upstream.
	return h.writeHangupRefusal(clientWriter, header)
}

// isAllowed reports whether the given IAX subclass is in the
// session's allowlist.
func (h *WriteGatedHandler) isAllowed(sub wire.IAXSubclass) bool {
	for _, a := range h.Allowed {
		if a.Subclass == sub {
			return true
		}
	}
	return false
}

// writeHangupRefusal emits a HANGUP full-frame back to the
// client. The HANGUP terminates whatever call-dialogue the client
// was attempting, which is the gate's preferred refusal.
//
// We set:
//
//	Src = the request's Dst (0 for NEW — the callee's assigned
//	      number hasn't been issued yet)
//	Dst = the request's Src (mirrored; the client knows this
//	      number)
//	Timestamp = the request's Timestamp (reflect, per RFC 5456)
//	OSeqno / ISeqno = the request's counterparts inverted
//	FrameType = IAX, Subclass = HANGUP
func (h *WriteGatedHandler) writeHangupRefusal(w io.Writer, req wire.Header) error {
	buf := make([]byte, wire.HeaderLen)
	// SrcCallNum: we have no assigned number (we're not a real
	// PBX); mirror the request's Dst, which is what the client
	// proposed / knows.
	binary.BigEndian.PutUint16(buf[0:2], 0x8000|(req.DstCallNum&0x7FFF))
	// DstCallNum: the client's Src — so the client routes the
	// HANGUP to its pending call.
	binary.BigEndian.PutUint16(buf[2:4], req.SrcCallNum&0x7FFF)
	binary.BigEndian.PutUint32(buf[4:8], req.Timestamp)
	// Sequence numbers: OSeqno = req.ISeqno (we're replying), +1
	buf[8] = req.ISeqno + 1
	buf[9] = req.OSeqno
	buf[10] = byte(wire.FrameTypeIAX)
	buf[11] = byte(wire.IAXHangup)
	_, err := w.Write(buf)
	if err != nil {
		return fmt.Errorf("iax2: write HANGUP refusal: %w", err)
	}
	return nil
}
