//go:build offensive

package s7

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	s7wire "local/elsereno/internal/protocols/s7/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedFunction scopes the S7 function codes the operator
// authorises for the session (e.g. FuncWriteVar, FuncPLCStop).
type AllowedFunction struct {
	FC s7wire.FunctionCode
}

// AllowedWriteItem scopes a WriteVar request to a specific
// (Area, DB, address-range) tuple. v1.52 chunk 1.
//
// Semantics: when AllowedWriteItems is non-empty, a
// FuncWriteVar (0x05) request is forwarded ONLY when:
//
//   - FuncWriteVar is in the AllowedFunction list AND
//   - EVERY parsed item's (Area, DB, [ByteAddr,
//     ByteAddr+Length-1]) range falls inside at least
//     one AllowedWriteItem.
//
// Multi-item WriteVars are gated as a unit — one
// disallowed item refuses the whole frame. This matches
// the operator's mental model: the WriteVar is one
// transaction, and partial allow would be confusing.
//
// Other write-class FCs (PLCStop, RequestDownload,
// DownloadBlock, etc.) are NOT constrained by AllowedWriteItems
// — those don't carry an item list. Their gate stays at the
// FuncCode level via AllowedFunction.
//
// Empty list → v1.27 behaviour: WriteVar passes if
// FuncWriteVar is in AllowedFunction, regardless of
// target address. Operators who care about per-address
// scoping populate AllowedWriteItems; everyone else gets
// the v1.27 surface.
type AllowedWriteItem struct {
	// Area is the S7 area code (0x81=I, 0x82=Q, 0x83=M,
	// 0x84=DB, 0x85=DI, 0x86=L, 0x87=V).
	Area uint8
	// DB is the DB number. Ignored for non-DB areas (the
	// gate matches Area first, then DB if Area==0x84
	// or 0x85).
	DB uint16
	// AddrStart / AddrEnd is the inclusive byte-address
	// range. AddrEnd == AddrStart is a single-byte
	// allowlist.
	AddrStart uint32
	AddrEnd   uint32
}

// Matches reports whether the given WriteItem falls
// within this AllowedWriteItem. The item's full byte
// range [ByteAddr, ByteAddr+Length-1] must fit; partial
// overlaps refuse.
func (a AllowedWriteItem) Matches(item s7wire.WriteItem) bool {
	if a.Area != item.Area {
		return false
	}
	// DB number matters for DB / DI areas only.
	if a.Area == 0x84 || a.Area == 0x85 {
		if a.DB != item.DB {
			return false
		}
	}
	itemStart := item.ByteAddr
	itemEnd := item.ByteAddr
	if item.Length > 0 {
		itemEnd = item.ByteAddr + item.Length - 1
	}
	return itemStart >= a.AddrStart && itemEnd <= a.AddrEnd
}

// allowlistSeparatorWriteItems isolates the per-item
// hash block from the per-function block in
// AllowlistHash. Picked from the high range so it can't
// collide with any S7 FunctionCode value (FCs are
// 0x00..0x29).
const allowlistSeparatorWriteItems = 0xF1

// AllowlistHash returns the deterministic SHA-256 over
// target + sorted function allowlist + sorted write-item
// allowlist.
//
// Layout: target || 0x00 || FC × sorted_funcs ||
// (0xF1 || separator block × sorted_writeItems) when
// non-empty.
//
// The 0xF1 separator means operators with empty
// AllowedWriteItems keep the v1.27 hash; the per-item
// dimension only changes the token when actually
// configured. Backwards-compat with pre-v1.52 dry-run
// tokens.
func AllowlistHash(target string, allowed []AllowedFunction, items []AllowedWriteItem) [32]byte {
	sortedFuncs := append([]AllowedFunction(nil), allowed...)
	sort.Slice(sortedFuncs, func(i, j int) bool { return sortedFuncs[i].FC < sortedFuncs[j].FC })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedFuncs {
		_, _ = h.Write([]byte{byte(a.FC)})
	}
	if len(items) > 0 {
		sortedItems := append([]AllowedWriteItem(nil), items...)
		sort.Slice(sortedItems, func(i, j int) bool {
			a, b := sortedItems[i], sortedItems[j]
			if a.Area != b.Area {
				return a.Area < b.Area
			}
			if a.DB != b.DB {
				return a.DB < b.DB
			}
			if a.AddrStart != b.AddrStart {
				return a.AddrStart < b.AddrStart
			}
			return a.AddrEnd < b.AddrEnd
		})
		_, _ = h.Write([]byte{allowlistSeparatorWriteItems})
		var buf [11]byte
		for _, it := range sortedItems {
			buf[0] = it.Area
			binary.BigEndian.PutUint16(buf[1:3], it.DB)
			binary.BigEndian.PutUint32(buf[3:7], it.AddrStart)
			binary.BigEndian.PutUint32(buf[7:11], it.AddrEnd)
			_, _ = h.Write(buf[:])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
//
// Backward-compat shim: callers pre-v1.52 used a 2-arg
// version with (target, allowed). The v1.52 caller
// uses (target, allowed, items). To avoid a breaking
// signature change for the pre-existing CLI builder
// (which threads only the function allowlist), we leave
// this as the canonical form and expose
// SessionMutationLegacy below for any caller that
// genuinely doesn't have items to pass.
func SessionMutation(target string, allowed []AllowedFunction, items []AllowedWriteItem) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "s7",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed, items),
	}
}

// SessionMutationLegacy is the 2-arg form for callers
// who don't yet thread per-item allowlists. Yields the
// same hash as SessionMutation(target, allowed, nil) so
// pre-v1.52 confirm-tokens keep validating.
func SessionMutationLegacy(target string, allowed []AllowedFunction) confirm.Mutation {
	return SessionMutation(target, allowed, nil)
}

// ErrSessionNotAuthorised is returned by Handle before Authorise.
var ErrSessionNotAuthorised = errors.New("s7: write-gated proxy requires Authorise() first")

// WriteGatedHandler routes S7 writes through the ADR-039 triple-
// confirm wrapper. Session-level Authorise runs once; per-frame
// decisions consult the authorised allowlist.
type WriteGatedHandler struct {
	Target  string
	Allowed []AllowedFunction
	// AllowedWriteItems is the optional v1.52 chunk-1 per-(area,
	// db, addr) allowlist for FuncWriteVar requests. When
	// non-empty, EVERY parsed item in a WriteVar must fall
	// within at least one entry; partial / no-match refuses
	// the whole frame. Empty list preserves v1.27 FC-only
	// gating for WriteVar (operators without per-address
	// constraints aren't forced to populate this).
	AllowedWriteItems []AllowedWriteItem

	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every TPKT envelope that crosses the gate is
	// timestamped + direction-tagged + persisted. Wrapping
	// happens BEFORE the TPKT/COTP parser reads, so wire-aware
	// allowlist routing is captured intact. Nil disables
	// recording — the gate behaves exactly as it did pre-v1.30.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed, h.AllowedWriteItems)
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

// forward reads one TPKT envelope at a time; forwards allowed
// functions and refuses anything else with the same S7 AckData
// err-class 0x85 / code 0x01 the default build uses.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		tpkt, err := s7wire.ReadTPKT(client)
		if err != nil {
			return err
		}
		if h.shouldForward(tpkt.Payload) {
			if werr := s7wire.WriteTPKT(upstream, tpkt.Payload); werr != nil {
				return werr
			}
			continue
		}
		refusal := s7wire.BuildRefusalPayload(innerPDU(tpkt.Payload))
		if werr := s7wire.WriteTPKT(clientWriter, refusal); werr != nil {
			return werr
		}
	}
}

// shouldForward returns true when the COTP payload represents a
// CategoryRead S7 function OR a CategoryWrite whose FC appears in
// the authorised allowlist (and, for FuncWriteVar with a non-
// empty AllowedWriteItems, every item is in range).
func (h *WriteGatedHandler) shouldForward(payload []byte) bool {
	t, ok := s7wire.COTPType(payload)
	if !ok {
		return false
	}
	if t != s7wire.COTPData {
		// Non-DT COTP PDUs (CR, CC, DR) forward untouched so the
		// handshake completes.
		return true
	}
	inner := innerPDU(payload)
	fc, ok := s7wire.ExtractFunctionCode(inner)
	if !ok {
		return false
	}
	switch s7wire.Classify(fc) {
	case s7wire.CategoryRead:
		return true
	case s7wire.CategoryWrite:
		if !h.fcAllowed(fc) {
			return false
		}
		// v1.52: per-item gate for FuncWriteVar only when
		// the operator opted in (AllowedWriteItems non-empty).
		if fc == s7wire.FuncWriteVar && len(h.AllowedWriteItems) > 0 {
			return h.writeItemsAllowed(inner)
		}
		return true
	case s7wire.CategoryUnknown:
		return false
	}
	return false
}

// fcAllowed reports whether fc is in the AllowedFunction list.
func (h *WriteGatedHandler) fcAllowed(fc s7wire.FunctionCode) bool {
	for _, a := range h.Allowed {
		if a.FC == fc {
			return true
		}
	}
	return false
}

// writeItemsAllowed parses the WriteVar item list from the inner
// S7 PDU and returns true iff EVERY item fits within at least one
// AllowedWriteItem entry. A parse failure (malformed PDU,
// truncated item, unsupported syntax) is treated as refuse —
// the gate doesn't allow what it can't fully classify.
func (h *WriteGatedHandler) writeItemsAllowed(inner []byte) bool {
	items, err := s7wire.ParseWriteVarItems(inner)
	if err != nil || len(items) == 0 {
		return false
	}
	for _, item := range items {
		if !h.itemAllowed(item) {
			return false
		}
	}
	return true
}

// itemAllowed reports whether item falls inside at least one
// AllowedWriteItem entry.
func (h *WriteGatedHandler) itemAllowed(item s7wire.WriteItem) bool {
	for _, a := range h.AllowedWriteItems {
		if a.Matches(item) {
			return true
		}
	}
	return false
}

// innerPDU slices the S7 PDU portion out of a COTP DT TPKT payload
// using the same layout the default write-ban handler uses.
func innerPDU(payload []byte) []byte {
	if len(payload) < 3 {
		return payload
	}
	li := int(payload[0])
	s7Start := li + 1
	if s7Start >= len(payload) {
		return payload
	}
	return payload[s7Start:]
}
