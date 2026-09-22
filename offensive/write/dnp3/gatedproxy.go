//go:build offensive

// Package dnp3 hosts the DNP3 write-gated proxy handler. It classifies
// traffic at the link layer (primary function code) and the
// application layer (function code, plus the Control Relay Output
// Block carried by Operate / Direct Operate), scopes control by
// destination link address and by (point-index, control-code), and
// refuses anything outside the operator's allowlist with a well-formed
// IIN2 FUNC_NOT_SUPP response.
package dnp3

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"math"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedControl scopes DNP3 link-layer primary function codes.
type AllowedControl struct {
	// PrimaryFC is the link-layer primary function (0 Reset Link,
	// 1 Test Link, 3 Confirmed Data, 4 Unconfirmed Data, 9 Request
	// Link Status).
	PrimaryFC uint8
}

// LinkPair pins one master->outstation link-address pair. A zero field
// matches any address (so Src=0 accepts any master, Dest=0 any
// outstation). When a session carries at least one LinkPair, a
// mutating frame whose (Src, Dest) matches no entry is refused: the
// poster's "control FC from a non-master link address is the finding".
type LinkPair struct {
	Src  uint16
	Dest uint16
}

// AllowedCROBControl scopes a Control Relay Output Block to a range of
// point indices and, optionally, a set of exact control codes. When a
// session carries at least one entry, every CROB in an Operate /
// Direct Operate must match one: its index in [IndexStart, IndexEnd]
// and, when Codes is non-empty, its control code in Codes. An empty
// Codes accepts any control code on that index range.
//
// This is the poster's central lever: an operator can allow LATCH_ON /
// LATCH_OFF on points 5-8 and still refuse TRIP (0x81) or CLOSE (0x41)
// on any breaker.
type AllowedCROBControl struct {
	IndexStart uint16
	IndexEnd   uint16
	Codes      []uint8
}

// AllowedAnalogControl scopes a g41 Analog Output Block (a setpoint) to
// a range of point indices and, optionally, a value window. When a
// session carries at least one entry, every setpoint in an Operate /
// Direct Operate must match one: its index in [IndexStart, IndexEnd]
// and, when Bounded, its value in [Min, Max]. An unbounded entry
// accepts any value on that index range.
//
// This is the analog analogue of AllowedCROBControl: an operator can
// let a valve be driven between 0 and 50 percent while refusing a
// setpoint that would slam it fully open.
type AllowedAnalogControl struct {
	IndexStart uint16
	IndexEnd   uint16
	Bounded    bool
	Min, Max   float64
}

// Allowlist is the full set of dimensions a DNP3 proxy session binds
// into its confirm-token.
type Allowlist struct {
	// Control lists the link-layer primary function codes accepted.
	Control []AllowedControl
	// AppFC lists the application-layer function codes accepted inside
	// user-data frames (Read is always accepted and needs no entry).
	AppFC []AllowedAppFunction
	// Links pins the accepted master->outstation link-address pairs.
	Links []LinkPair
	// ControlOutput scopes CROBs by (index-range, control-code).
	ControlOutput []AllowedCROBControl
	// AnalogOutput scopes g41 setpoints by (index-range, value-window).
	AnalogOutput []AllowedAnalogControl
}

// AllowlistHash returns the deterministic SHA-256 that binds a session
// token to its target + allowlist. The link-layer primary-FC block is
// always present; the application-FC, link-pair and CROB blocks are
// folded in only when non-empty, each behind a distinct tag byte, so a
// session that uses none of them hashes identically to the original
// primary-FC-only form (backwards-compatible tokens).
func AllowlistHash(target string, a Allowlist) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})

	ctrl := append([]AllowedControl(nil), a.Control...)
	sort.Slice(ctrl, func(i, j int) bool { return ctrl[i].PrimaryFC < ctrl[j].PrimaryFC })
	for _, c := range ctrl {
		_, _ = h.Write([]byte{c.PrimaryFC})
	}

	hashAppFC(h, a.AppFC)
	hashLinks(h, a.Links)
	hashControlOutput(h, a.ControlOutput)
	hashAnalogOutput(h, a.AnalogOutput)

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// hashAppFC folds the sorted application-FC allowlist behind tag 0xAF.
func hashAppFC(h hash.Hash, appFC []AllowedAppFunction) {
	if len(appFC) == 0 {
		return
	}
	_, _ = h.Write([]byte{0xAF})
	fcs := make([]uint8, 0, len(appFC))
	for _, f := range appFC {
		fcs = append(fcs, f.FC)
	}
	sortBytes(fcs)
	_, _ = h.Write(fcs)
}

// hashLinks folds the sorted link-pair pins behind tag 0x11.
func hashLinks(h hash.Hash, links []LinkPair) {
	if len(links) == 0 {
		return
	}
	_, _ = h.Write([]byte{0x11})
	ls := append([]LinkPair(nil), links...)
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].Src != ls[j].Src {
			return ls[i].Src < ls[j].Src
		}
		return ls[i].Dest < ls[j].Dest
	})
	var b [4]byte
	for _, lp := range ls {
		binary.BigEndian.PutUint16(b[0:2], lp.Src)
		binary.BigEndian.PutUint16(b[2:4], lp.Dest)
		_, _ = h.Write(b[:])
	}
}

// hashControlOutput folds the sorted CROB scopes behind tag 0xC0.
func hashControlOutput(h hash.Hash, out []AllowedCROBControl) {
	if len(out) == 0 {
		return
	}
	_, _ = h.Write([]byte{0xC0})
	crobs := make([]AllowedCROBControl, len(out))
	copy(crobs, out)
	for i := range crobs {
		codes := append([]uint8(nil), crobs[i].Codes...)
		sortBytes(codes)
		crobs[i].Codes = codes
	}
	sort.Slice(crobs, func(i, j int) bool {
		if crobs[i].IndexStart != crobs[j].IndexStart {
			return crobs[i].IndexStart < crobs[j].IndexStart
		}
		if crobs[i].IndexEnd != crobs[j].IndexEnd {
			return crobs[i].IndexEnd < crobs[j].IndexEnd
		}
		return string(crobs[i].Codes) < string(crobs[j].Codes)
	})
	var b [4]byte
	for _, cr := range crobs {
		binary.BigEndian.PutUint16(b[0:2], cr.IndexStart)
		binary.BigEndian.PutUint16(b[2:4], cr.IndexEnd)
		_, _ = h.Write(b[:])
		// #nosec G115 -- Codes is an operator-listed control-code set, never near 256
		_, _ = h.Write([]byte{byte(len(cr.Codes))})
		_, _ = h.Write(cr.Codes)
	}
}

// hashAnalogOutput folds the sorted g41 setpoint scopes behind tag 0xA0.
func hashAnalogOutput(h hash.Hash, out []AllowedAnalogControl) {
	if len(out) == 0 {
		return
	}
	_, _ = h.Write([]byte{0xA0})
	aos := append([]AllowedAnalogControl(nil), out...)
	sort.Slice(aos, func(i, j int) bool {
		if aos[i].IndexStart != aos[j].IndexStart {
			return aos[i].IndexStart < aos[j].IndexStart
		}
		if aos[i].IndexEnd != aos[j].IndexEnd {
			return aos[i].IndexEnd < aos[j].IndexEnd
		}
		if aos[i].Bounded != aos[j].Bounded {
			return !aos[i].Bounded
		}
		if aos[i].Min != aos[j].Min {
			return aos[i].Min < aos[j].Min
		}
		return aos[i].Max < aos[j].Max
	})
	var b [8]byte
	for _, a := range aos {
		binary.BigEndian.PutUint16(b[0:2], a.IndexStart)
		binary.BigEndian.PutUint16(b[2:4], a.IndexEnd)
		_, _ = h.Write(b[0:4])
		flag := byte(0)
		if a.Bounded {
			flag = 1
		}
		_, _ = h.Write([]byte{flag})
		binary.BigEndian.PutUint64(b[:8], math.Float64bits(a.Min))
		_, _ = h.Write(b[:8])
		binary.BigEndian.PutUint64(b[:8], math.Float64bits(a.Max))
		_, _ = h.Write(b[:8])
	}
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, a Allowlist) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "dnp3",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, a),
	}
}

// sortBytes sorts a byte slice in place ascending.
func sortBytes(b []uint8) {
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
}
