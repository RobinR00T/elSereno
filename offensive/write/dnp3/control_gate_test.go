//go:build offensive

package dnp3

import (
	"encoding/binary"
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

// hdr builds a primary unconfirmed-user-data header (control 0xC4) with
// the given link addresses. Length is unused by shouldForward.
func hdr(dest, src uint16) wire.Header {
	return wire.Header{Control: 0xC4, Dest: dest, Src: src}
}

// apdu builds a de-blocked application payload: transport + AC + FC +
// objects.
func apdu(fc uint8, objects []byte) []byte {
	return append([]byte{0xC0, 0xC0, fc}, objects...)
}

// crobObjects builds a single-point g12v1 CROB (qualifier 0x17) at the
// given index with the given control code.
func crobObjects(index, code uint8) []byte {
	obj := []byte{12, 1, 0x17, 0x01, index}
	crob := make([]byte, 11)
	crob[0] = code
	return append(obj, crob...)
}

// aobObjects builds a single-point g41v1 Analog Output Block (int32,
// qualifier 0x17) at the given index with the given setpoint value.
func aobObjects(index uint8, v int32) []byte {
	obj := []byte{41, 1, 0x17, 0x01, index}
	var b [4]byte
	// #nosec G115 -- int32->uint32 bit reinterpretation for LE encoding (test)
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	obj = append(obj, b[:]...)
	return append(obj, 0x00) // control status
}

// TestGate_AnalogScoping proves the (index-range, value-window) scope:
// an in-range in-bounds setpoint passes, out-of-bounds and out-of-range
// are refused, and a CROB is refused when only analog scope is set.
func TestGate_AnalogScoping(t *testing.T) {
	t.Parallel()
	h := &WriteGatedHandler{
		AllowedAppFC: []AllowedAppFunction{{FC: AppFCDirectOperate}},
		AllowedAnalogOutput: []AllowedAnalogControl{
			{IndexStart: 10, IndexEnd: 12, Bounded: true, Min: 0, Max: 5000},
		},
	}
	// In range, in bounds: allowed.
	if !h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, aobObjects(10, 3000))) {
		t.Fatal("in-bounds setpoint on point 10 should pass")
	}
	// Value above the window: refused.
	if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, aobObjects(10, 9000))) {
		t.Fatal("setpoint 9000 above Max=5000 must be refused")
	}
	// Out-of-range index: refused.
	if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, aobObjects(99, 100))) {
		t.Fatal("setpoint on out-of-range point 99 must be refused")
	}
	// A CROB when only analog scope is configured: refused (CROBs not
	// authorised in this session).
	if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, crobObjects(10, wire.OpLatchOn))) {
		t.Fatal("CROB must be refused when only analog scope is set")
	}
}

// TestGate_AnalogUnboundedAnyValue proves an unbounded entry accepts
// any value on its index range.
func TestGate_AnalogUnboundedAnyValue(t *testing.T) {
	t.Parallel()
	h := &WriteGatedHandler{
		AllowedAppFC:        []AllowedAppFunction{{FC: AppFCDirectOperate}},
		AllowedAnalogOutput: []AllowedAnalogControl{{IndexStart: 10, IndexEnd: 12}},
	}
	if !h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, aobObjects(11, 999999))) {
		t.Fatal("unbounded analog scope should accept any value in range")
	}
}

// TestAllowlistHash_AnalogBindsToToken proves the analog scope folds
// into the token hash (adding it changes the hash; empty does not).
func TestAllowlistHash_AnalogBindsToToken(t *testing.T) {
	t.Parallel()
	target := "10.0.0.1:20000"
	base := Allowlist{Control: []AllowedControl{{PrimaryFC: 4}}}
	withAnalog := base
	withAnalog.AnalogOutput = []AllowedAnalogControl{{IndexStart: 10, IndexEnd: 12, Bounded: true, Min: 0, Max: 5000}}
	if AllowlistHash(target, base) == AllowlistHash(target, withAnalog) {
		t.Fatal("adding an analog scope must change the token hash")
	}
	// The bounds are bound: a different Max yields a different token.
	other := base
	other.AnalogOutput = []AllowedAnalogControl{{IndexStart: 10, IndexEnd: 12, Bounded: true, Min: 0, Max: 4000}}
	if AllowlistHash(target, withAnalog) == AllowlistHash(target, other) {
		t.Fatal("a different value bound must change the token hash")
	}
}

// TestGate_BroadcastControlRefused proves a control to a broadcast
// destination is refused even when the app FC + CROB are allowlisted.
func TestGate_BroadcastControlRefused(t *testing.T) {
	t.Parallel()
	h := &WriteGatedHandler{
		AllowedAppFC:         []AllowedAppFunction{{FC: AppFCDirectOperate}},
		AllowedControlOutput: []AllowedCROBControl{{IndexStart: 0, IndexEnd: 100}},
	}
	body := apdu(AppFCDirectOperate, crobObjects(5, wire.OpLatchOn))
	if h.shouldForward(hdr(0x0001, 0x0002), body) == false {
		t.Fatal("unicast DirectOperate should pass")
	}
	for _, bc := range []uint16{0xFFFD, 0xFFFE, 0xFFFF} {
		if h.shouldForward(hdr(bc, 0x0002), body) {
			t.Fatalf("broadcast dest 0x%04X control must be refused", bc)
		}
	}
}

// TestGate_LinkAddressPinning proves a mutating frame from an
// unpinned (src, dest) is refused.
func TestGate_LinkAddressPinning(t *testing.T) {
	t.Parallel()
	h := &WriteGatedHandler{
		AllowedAppFC: []AllowedAppFunction{{FC: AppFCWrite}},
		AllowedLink:  []LinkPair{{Src: 2, Dest: 1}},
	}
	body := apdu(AppFCWrite, []byte{0x00})
	if !h.shouldForward(hdr(1, 2), body) {
		t.Fatal("pinned (src=2,dest=1) Write should pass")
	}
	if h.shouldForward(hdr(1, 99), body) {
		t.Fatal("Write from unpinned src=99 must be refused")
	}
	if h.shouldForward(hdr(7, 2), body) {
		t.Fatal("Write to unpinned dest=7 must be refused")
	}
	// A read from an unpinned source still passes (pins gate mutations).
	if !h.shouldForward(hdr(1, 99), apdu(AppFCRead, []byte{0x00})) {
		t.Fatal("Read must not be blocked by link pinning")
	}
}

// TestGate_CROBScoping proves the (index-range, control-code) scope:
// LATCH on an in-range point passes, TRIP is refused, and out-of-range
// is refused.
func TestGate_CROBScoping(t *testing.T) {
	t.Parallel()
	h := &WriteGatedHandler{
		AllowedAppFC: []AllowedAppFunction{{FC: AppFCDirectOperate}},
		AllowedControlOutput: []AllowedCROBControl{
			{IndexStart: 5, IndexEnd: 8, Codes: []uint8{wire.OpLatchOn, wire.OpLatchOff}},
		},
	}
	// LATCH_ON (0x03) on point 5: allowed.
	if !h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, crobObjects(5, wire.OpLatchOn))) {
		t.Fatal("LATCH_ON on in-scope point 5 should pass")
	}
	// TRIP (0x81) on point 5: refused (code not in the allowlist).
	if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, crobObjects(5, 0x81))) {
		t.Fatal("TRIP (0x81) on point 5 must be refused")
	}
	// LATCH_ON on point 9: refused (index out of range).
	if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, crobObjects(9, wire.OpLatchOn))) {
		t.Fatal("LATCH_ON on out-of-range point 9 must be refused")
	}
	// A control carrying no parseable CROB under enforcement: refused.
	if h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, []byte{30, 1, 0x06})) {
		t.Fatal("control with no CROB under scoping must be refused")
	}
}

// TestGate_CROBScopingDisabledFallsBackToFC proves that without any
// AllowedControlOutput, an allowlisted Operate passes regardless of the
// control code (FC-level decision, backwards-compatible).
func TestGate_CROBScopingDisabledFallsBackToFC(t *testing.T) {
	t.Parallel()
	h := &WriteGatedHandler{
		AllowedAppFC: []AllowedAppFunction{{FC: AppFCDirectOperate}},
	}
	if !h.shouldForward(hdr(1, 2), apdu(AppFCDirectOperate, crobObjects(5, 0x81))) {
		t.Fatal("without CROB scoping, an allowlisted DirectOperate should pass")
	}
}

// TestAllowlistHash_BackwardCompat proves the extra dimensions fold in
// only when non-empty: a control-only allowlist hashes identically
// whether the empty extras are present or not, and adding any extra
// changes the hash.
func TestAllowlistHash_BackwardCompat(t *testing.T) {
	t.Parallel()
	target := "10.0.0.1:20000"
	base := Allowlist{Control: []AllowedControl{{PrimaryFC: 4}}}
	if AllowlistHash(target, base) != AllowlistHash(target, Allowlist{
		Control: []AllowedControl{{PrimaryFC: 4}}, AppFC: nil, Links: nil, ControlOutput: nil,
	}) {
		t.Fatal("empty extras must not change the hash")
	}
	withApp := base
	withApp.AppFC = []AllowedAppFunction{{FC: AppFCWrite}}
	withLink := base
	withLink.Links = []LinkPair{{Src: 2, Dest: 1}}
	withCROB := base
	withCROB.ControlOutput = []AllowedCROBControl{{IndexStart: 5, IndexEnd: 8}}
	for name, a := range map[string]Allowlist{"app": withApp, "link": withLink, "crob": withCROB} {
		if AllowlistHash(target, base) == AllowlistHash(target, a) {
			t.Fatalf("adding %s dimension must change the hash", name)
		}
	}
}

// TestAllowlistHash_OrderInsensitive proves the hash is stable under
// reordering of every dimension.
func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	t.Parallel()
	target := "10.0.0.1:20000"
	a := Allowlist{
		Control:       []AllowedControl{{PrimaryFC: 4}, {PrimaryFC: 3}},
		AppFC:         []AllowedAppFunction{{FC: 0x05}, {FC: 0x02}},
		Links:         []LinkPair{{Src: 2, Dest: 1}, {Src: 1, Dest: 2}},
		ControlOutput: []AllowedCROBControl{{IndexStart: 5, IndexEnd: 8, Codes: []uint8{0x04, 0x03}}},
	}
	b := Allowlist{
		Control:       []AllowedControl{{PrimaryFC: 3}, {PrimaryFC: 4}},
		AppFC:         []AllowedAppFunction{{FC: 0x02}, {FC: 0x05}},
		Links:         []LinkPair{{Src: 1, Dest: 2}, {Src: 2, Dest: 1}},
		ControlOutput: []AllowedCROBControl{{IndexStart: 5, IndexEnd: 8, Codes: []uint8{0x03, 0x04}}},
	}
	if AllowlistHash(target, a) != AllowlistHash(target, b) {
		t.Fatal("AllowlistHash must be order-insensitive across all dimensions")
	}
}
