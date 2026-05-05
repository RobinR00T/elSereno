//go:build offensive

package enip

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	enipwire "local/elsereno/internal/protocols/enip/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedCommand scopes an EIP encapsulation command the operator
// authorises for the session (e.g. CmdSendRRData).
type AllowedCommand struct {
	Cmd uint16
}

// AllowedAttribute scopes an MR request inside a SendRRData /
// SendUnitData to a specific (Class, Instance, Attribute)
// triple. v1.53 chunk 1.
//
// Semantics: when AllowedAttributes is non-empty AND the
// encapsulated command is SendRRData or SendUnitData, the
// gate parses the EPATH inside the MR request and admits
// the frame ONLY when the (Class, Instance, Attribute)
// matches at least one entry.
//
// MatchType encodes how strict the match is:
//   - exact          — Class, Instance, Attribute all match.
//   - class+instance — Class + Instance match; Attribute
//     wildcarded (the op targets the
//     whole instance, e.g. Forward_Open
//     on an assembly).
//   - class-only     — Class matches; Instance + Attribute
//     wildcarded (operator allows ALL
//     instances of a vendor object).
//
// Empty list preserves v1.27 command-level gating.
type AllowedAttribute struct {
	Class     uint32
	Instance  uint32
	Attribute uint32
	// MatchType controls wildcarding. See package
	// comment.
	MatchType AllowedAttrMatch
}

// AllowedAttrMatch enumerates the allowlist match
// strictnesses.
type AllowedAttrMatch uint8

// AllowedAttrMatch values.
const (
	// MatchExact requires Class + Instance + Attribute
	// to all match the request.
	MatchExact AllowedAttrMatch = iota
	// MatchClassInstance requires Class + Instance to
	// match; Attribute is wildcarded.
	MatchClassInstance
	// MatchClassOnly requires only Class to match;
	// Instance + Attribute are wildcarded.
	MatchClassOnly
)

// Matches reports whether t falls within this
// AllowedAttribute. A request that doesn't carry a
// segment we required (e.g. exact match needs all 3
// segments) doesn't match.
func (a AllowedAttribute) Matches(t enipwire.EPathTarget) bool {
	if !t.HasClass || a.Class != t.Class {
		return false
	}
	switch a.MatchType {
	case MatchClassOnly:
		return true
	case MatchClassInstance:
		return t.HasInstance && a.Instance == t.Instance
	case MatchExact:
		return t.HasInstance && t.HasAttr &&
			a.Instance == t.Instance && a.Attribute == t.Attribute
	}
	return false
}

// allowlistSeparatorAttrs isolates the per-attribute hash
// block from the per-command block. Picked from the high
// range so it can't collide with an EIP command code
// (commands are 0x00..0xFF but only 0x04..0x70 used).
const allowlistSeparatorAttrs = 0xF2

// AllowlistHash returns the deterministic SHA-256 over
// target + sorted command allowlist + sorted attribute
// allowlist. Empty attrs list yields the v1.27 hash for
// backwards-compat.
func AllowlistHash(target string, allowed []AllowedCommand, attrs []AllowedAttribute) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Cmd < sorted[j].Cmd })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [2]byte
	for _, a := range sorted {
		binary.LittleEndian.PutUint16(buf[:], a.Cmd)
		_, _ = h.Write(buf[:])
	}
	if len(attrs) > 0 {
		sortedAttrs := append([]AllowedAttribute(nil), attrs...)
		sort.Slice(sortedAttrs, func(i, j int) bool {
			a, b := sortedAttrs[i], sortedAttrs[j]
			if a.Class != b.Class {
				return a.Class < b.Class
			}
			if a.Instance != b.Instance {
				return a.Instance < b.Instance
			}
			if a.Attribute != b.Attribute {
				return a.Attribute < b.Attribute
			}
			return a.MatchType < b.MatchType
		})
		_, _ = h.Write([]byte{allowlistSeparatorAttrs})
		var attrBuf [13]byte
		for _, at := range sortedAttrs {
			binary.LittleEndian.PutUint32(attrBuf[0:4], at.Class)
			binary.LittleEndian.PutUint32(attrBuf[4:8], at.Instance)
			binary.LittleEndian.PutUint32(attrBuf[8:12], at.Attribute)
			attrBuf[12] = byte(at.MatchType)
			_, _ = h.Write(attrBuf[:])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedCommand, attrs []AllowedAttribute) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "enip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed, attrs),
	}
}

// SessionMutationLegacy is the 2-arg form for callers
// who don't yet thread per-attribute allowlists. Yields
// the same hash as SessionMutation(target, allowed, nil).
func SessionMutationLegacy(target string, allowed []AllowedCommand) confirm.Mutation {
	return SessionMutation(target, allowed, nil)
}

// ErrSessionNotAuthorised is returned by Handle before Authorise.
var ErrSessionNotAuthorised = errors.New("enip: write-gated proxy requires Authorise() first")

// WriteGatedHandler routes ENIP writes through the ADR-039 wrapper.
type WriteGatedHandler struct {
	Target  string
	Allowed []AllowedCommand
	// AllowedAttributes is the optional v1.53 chunk-1 per-(class,
	// instance, attribute) allowlist for SendRRData / SendUnitData
	// MR requests. When non-empty AND the command is one of those
	// two, the EPATH inside the MR is parsed and the request is
	// admitted only if its (class, instance, attribute) triple
	// matches at least one entry. Empty list preserves v1.27
	// command-level gating.
	AllowedAttributes []AllowedAttribute

	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every byte that crosses the gate is
	// timestamped + direction-tagged + persisted. Wrapping
	// happens BEFORE the encapsulation-packet parser reads,
	// so wire-aware allowlist routing is captured intact. Nil
	// disables recording — the gate behaves exactly as it did
	// pre-v1.30.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed, h.AllowedAttributes)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

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

func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		hdr, body, err := enipwire.ReadPacket(client)
		if err != nil {
			return err
		}
		if h.shouldForward(hdr, body) {
			buf := enipwire.MarshalHeader(hdr)
			if _, werr := upstream.Write(buf[:]); werr != nil {
				return werr
			}
			if len(body) > 0 {
				if _, werr := upstream.Write(body); werr != nil {
					return werr
				}
			}
			continue
		}
		if _, werr := clientWriter.Write(enipwire.BuildRefusal(hdr)); werr != nil {
			return werr
		}
	}
}

func (h *WriteGatedHandler) shouldForward(hdr enipwire.Header, body []byte) bool {
	switch enipwire.Classify(hdr.Command) {
	case enipwire.CategoryRead:
		return true
	case enipwire.CategoryWrite:
		if !h.cmdAllowed(hdr.Command) {
			return false
		}
		// v1.53 chunk 1: per-(class, instance, attribute)
		// gate fires for SendRRData/SendUnitData when the
		// operator opted in. Other write-class commands
		// (e.g. RegisterSession, UnregisterSession) keep
		// command-level gating.
		if len(h.AllowedAttributes) > 0 &&
			(hdr.Command == enipwire.CmdSendRRData ||
				hdr.Command == enipwire.CmdSendUnitData) {
			return h.attributeAllowed(body)
		}
		return true
	case enipwire.CategoryUnknown:
		return false
	}
	return false
}

// cmdAllowed reports whether cmd is in the AllowedCommand list.
func (h *WriteGatedHandler) cmdAllowed(cmd uint16) bool {
	for _, a := range h.Allowed {
		if a.Cmd == cmd {
			return true
		}
	}
	return false
}

// attributeAllowed parses the MR target from the encapsulation
// body and returns true iff at least one AllowedAttribute
// entry matches. A parse failure (truncated body, unknown
// EPATH segment) returns false — the gate refuses what it
// can't classify.
func (h *WriteGatedHandler) attributeAllowed(body []byte) bool {
	target, ok := enipwire.ExtractMRTarget(body)
	if !ok {
		return false
	}
	for _, a := range h.AllowedAttributes {
		if a.Matches(target) {
			return true
		}
	}
	return false
}
