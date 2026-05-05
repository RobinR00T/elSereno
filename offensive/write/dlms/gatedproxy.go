//go:build offensive

// Package dlms implements the offensive write-gate proxy for
// DLMS/COSEM over TCP on TCP/4059. DLMS/COSEM (IEC 62056) is the
// dominant European smart-meter application protocol, used for
// AMI/AMR (Advanced Metering Infrastructure / Reading) data
// exchange. Operators speak it from utility back-offices to
// smart electricity, gas, water, and heat meters in residential
// and industrial deployments.
//
// SET-Request and ACTION-Request can: re-tariff via tariff
// register writes, cut/restore service via the Disconnect Control
// object (OBIS 0-0:96.50.0*255), reconfigure security
// (OBIS 0-0:43.0.0*255), trigger firmware updates via the Image
// Transfer object, change clock + DST rules, and modify
// scheduled disconnect events. Per-COSEM-object gating lets
// operators authorise tariff updates without authorising service
// disconnect.
//
// Architecture follows the established WriteGatedHandler template
// (mirrors offensive/write/iax2 + offensive/write/mbustcp): per-
// session Authorise on the SHA-256 of a sorted allowlist, per-
// frame filtering at wire-parse time.
//
// Three-tier gate:
//
//  1. **APDU tag level** — refuse APDUs whose tag isn't in the
//     allowlist. Always-safe set: AARQ/AARE/RLRQ/RLRE
//     (association lifecycle), GET-Request/Response (read),
//     SET-Response/ACTION-Response (server-side echoes),
//     EXCEPTION-Response.
//
//  2. **COSEM target level** (SET / ACTION only) — refuse any
//     APDU whose (class-id, OBIS, member-id) tuple isn't
//     allowlisted. OBIS bytes equal to 255 in an allowlist
//     entry act as wildcards, so an entry like
//     {ClassID: 70, OBIS: {0, 0, 96, 255, 255, 255}, MemberID: 0}
//     allows the entire 0-0:96.* OBIS sub-tree.
//
//  3. **Member-id level** — MatchExact requires all of (class,
//     OBIS, member) to match; MatchClassOnly wildcards member +
//     OBIS; MatchClassOBIS wildcards only member. Mirrors enip's
//     MatchExact / MatchClassInstance / MatchClassOnly.
//
// Refusal mode: silent drop. DLMS has an EXCEPTION-Response
// APDU we could synthesise, but it's a deliberate protocol-
// level error that the meter would never emit — using it as a
// gate signal would deceive the operator about what's
// happening on the wire. Silent drop with the connection
// staying open lets the client time out cleanly.
//
// Out of scope (slated future):
//
//   - **Datablock / with-list SET variants.** Only the normal
//     CHOICE (0x01) is parsed. Datablock fragmentation +
//     with-list multi-target SETs would need a per-element
//     gate that walks the list. Operators sending those will
//     see the gate refuse them; the workaround is to issue
//     normal-CHOICE SETs.
//   - **GLO_/DED_ ciphered APDUs.** Refused at APDU-tag level.
//     Inline gating of ciphered SET requires the operator's
//     master key.
//   - **CLI flag plumbing** in cmd_write_offensive.go — same
//     pattern as v1.52/v1.53/v1.55/v1.56.
package dlms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	dlmswire "local/elsereno/internal/protocols/dlms/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedAPDU scopes one APDU tag the operator authorises. The
// always-safe set (AARQ/AARE/RLRQ/RLRE/GET/responses) doesn't
// need entries.
type AllowedAPDU struct {
	Tag byte
}

// CosemMatch picks how strict the COSEM target match is.
type CosemMatch uint8

const (
	// MatchExact requires class-id, OBIS, AND member-id to all
	// match. Tightest grain — typical for "the Disconnect
	// Control object's reconnect method only".
	MatchExact CosemMatch = iota
	// MatchClassOBIS wildcards only the member-id; class + OBIS
	// must match. Typical for "any attribute on the tariff
	// register object".
	MatchClassOBIS
	// MatchClassOnly wildcards OBIS + member-id; only class-id
	// matches. Loose grain — typical for "any Register class
	// (3) write".
	MatchClassOnly
)

// AllowedCosem scopes a COSEM target the operator authorises
// inside SET-Request / ACTION-Request APDUs. OBIS bytes equal
// to 255 act as wildcards regardless of MatchType (the OBIS
// canonical wildcard convention).
type AllowedCosem struct {
	ClassID   uint16
	OBIS      [6]byte
	MemberID  byte
	MatchType CosemMatch
}

// Matches reports whether this AllowedCosem permits the parsed
// COSEM target.
func (a AllowedCosem) Matches(t dlmswire.CosemTarget) bool {
	if a.ClassID != t.ClassID {
		return false
	}
	switch a.MatchType {
	case MatchClassOnly:
		return true
	case MatchClassOBIS:
		return obisMatches(a.OBIS, t.OBIS)
	case MatchExact:
		return obisMatches(a.OBIS, t.OBIS) && a.MemberID == t.MemberID
	}
	return false
}

// obisMatches reports whether the parsed-frame OBIS satisfies
// the allowlist OBIS, treating allowlist 255 bytes as
// wildcards.
func obisMatches(allow, observed [6]byte) bool {
	for i := 0; i < 6; i++ {
		if allow[i] == 0xFF {
			continue
		}
		if allow[i] != observed[i] {
			return false
		}
	}
	return true
}

// Hash separators — chosen in the high range so they can't
// collide with APDU tag values (max 0xD8) or OBIS bytes
// (any uint8).
const (
	allowlistSeparatorAPDU  byte = 0xE3
	allowlistSeparatorCosem byte = 0xE4
)

// AllowlistHash returns the deterministic SHA-256 of the
// (apdus, cosems) allowlist. Both lists are sorted before
// hashing so the operator's dry-run token is stable regardless
// of input order. Empty cosems list yields a hash determined
// only by apdus (operator who wants APDU-tag-level allowance
// without per-target narrowing).
func AllowlistHash(target string, apdus []AllowedAPDU, cosems []AllowedCosem) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	writeAPDUs(h, apdus)
	if len(cosems) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorCosem})
		writeCosems(h, cosems)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func writeAPDUs(h io.Writer, apdus []AllowedAPDU) {
	sorted := append([]AllowedAPDU(nil), apdus...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Tag < sorted[j].Tag })
	_, _ = h.Write([]byte{allowlistSeparatorAPDU})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.Tag})
	}
}

func writeCosems(h io.Writer, cosems []AllowedCosem) {
	sorted := append([]AllowedCosem(nil), cosems...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ClassID != sorted[j].ClassID {
			return sorted[i].ClassID < sorted[j].ClassID
		}
		if cmp := bytes.Compare(sorted[i].OBIS[:], sorted[j].OBIS[:]); cmp != 0 {
			return cmp < 0
		}
		if sorted[i].MemberID != sorted[j].MemberID {
			return sorted[i].MemberID < sorted[j].MemberID
		}
		return sorted[i].MatchType < sorted[j].MatchType
	})
	var buf [11]byte
	for _, c := range sorted {
		binary.BigEndian.PutUint16(buf[0:2], c.ClassID)
		copy(buf[2:8], c.OBIS[:])
		buf[8] = c.MemberID
		buf[9] = byte(c.MatchType)
		buf[10] = 0x00 // padding for fixed-size hash block
		_, _ = h.Write(buf[:])
	}
}

// SessionMutation builds the confirm.Mutation that authorises
// the proxy session.
func SessionMutation(target string, apdus []AllowedAPDU, cosems []AllowedCosem) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "dlms",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, apdus, cosems),
	}
}

// AllowlistHashWithGeneration is the v1.17-style cookie variant.
func AllowlistHashWithGeneration(target string, apdus []AllowedAPDU, cosems []AllowedCosem, generation uint32) [32]byte {
	if generation == 0 {
		return AllowlistHash(target, apdus, cosems)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	writeAPDUs(h, apdus)
	if len(cosems) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorCosem})
		writeCosems(h, cosems)
	}
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], generation)
	_, _ = h.Write([]byte{0xFC})
	_, _ = h.Write(u32[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithGeneration builds the confirm.Mutation
// with the token-generation cookie.
func SessionMutationWithGeneration(target string, apdus []AllowedAPDU, cosems []AllowedCosem, generation uint32) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "dlms",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithGeneration(target, apdus, cosems, generation),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// DLMS over TCP fail-closed proxy.
type WriteGatedHandler struct {
	Target        string
	AllowedAPDUs  []AllowedAPDU
	AllowedCosems []AllowedCosem
	// TokenGeneration is the v1.17-style cookie. Default 0
	// preserves the v1.57 base hash.
	TokenGeneration uint32
	Deriver         confirm.KeyDeriver
	Auditor         confirm.Auditor
	SessionConfirm  confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithGeneration(h.Target, h.AllowedAPDUs, h.AllowedCosems, h.TokenGeneration)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle without prior
// Authorise.
var ErrSessionNotAuthorised = errors.New("dlms: write-gated proxy requires Authorise() first")

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
	go func() { errs <- h.forward(client, upstream) }()
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

// forward reads frames from the client side and routes per
// policy.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer) error {
	for {
		f, err := dlmswire.ReadFrame(client)
		if err != nil {
			return err
		}
		if !h.shouldForward(f) {
			// Silent drop — see package doc for refusal rationale.
			continue
		}
		if _, werr := upstream.Write(f.Raw); werr != nil {
			return werr
		}
	}
}

// shouldForward returns true when the frame is a legitimate
// read/lifecycle APDU OR a SET/ACTION whose tag is allowlisted
// AND whose COSEM target matches.
func (h *WriteGatedHandler) shouldForward(f dlmswire.Frame) bool {
	if dlmswire.IsAlwaysSafeAPDU(f.APDUTag) {
		return true
	}
	if !h.apduTagAllowed(f.APDUTag) {
		return false
	}
	if f.APDUTag == dlmswire.APDUTagSetRequest {
		return h.setAllowed(f.APDU)
	}
	if f.APDUTag == dlmswire.APDUTagActionRequest {
		return h.actionAllowed(f.APDU)
	}
	// Other allowed APDU tags pass without per-target narrowing.
	return true
}

func (h *WriteGatedHandler) apduTagAllowed(tag byte) bool {
	for _, a := range h.AllowedAPDUs {
		if a.Tag == tag {
			return true
		}
	}
	return false
}

func (h *WriteGatedHandler) setAllowed(apdu []byte) bool {
	target, err := dlmswire.ParseSetRequest(apdu)
	if err != nil {
		return false
	}
	return h.cosemAllowed(target)
}

func (h *WriteGatedHandler) actionAllowed(apdu []byte) bool {
	target, err := dlmswire.ParseActionRequest(apdu)
	if err != nil {
		return false
	}
	return h.cosemAllowed(target)
}

func (h *WriteGatedHandler) cosemAllowed(target dlmswire.CosemTarget) bool {
	for _, c := range h.AllowedCosems {
		if c.Matches(target) {
			return true
		}
	}
	return false
}
