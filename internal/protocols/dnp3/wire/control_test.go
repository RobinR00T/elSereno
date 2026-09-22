package wire

import "testing"

// crob builds an 11-octet g12v1 object with the given control code.
func crob(code uint8) []byte {
	b := make([]byte, crobLen)
	b[0] = code // control code; rest (count/on/off/status) left zero
	return b
}

// TestExtractCROBs_IndexPrefixSinglePoint uses the poster's canonical
// single-point encoding: 0C 01 17 01 <index> <11-byte CROB>.
func TestExtractCROBs_IndexPrefixSinglePoint(t *testing.T) {
	t.Parallel()
	apdu := []byte{GroupBinaryOutputControl, VarCROB, 0x17, 0x01, 0x05}
	apdu = append(apdu, crob(0x81)...) // TRIP + PULSE_ON on index 5
	points, ok := ExtractCROBs(apdu)
	if !ok || len(points) != 1 {
		t.Fatalf("ExtractCROBs ok=%v points=%d, want ok=true 1", ok, len(points))
	}
	if points[0].Index != 5 || points[0].ControlCode != 0x81 {
		t.Fatalf("point = %+v, want {5, 0x81}", points[0])
	}
	if !CROBIsTripClose(0x81) || CROBTCC(0x81) != TCCTrip || CROBOpType(0x81) != OpPulseOn {
		t.Fatalf("0x81 decode wrong: trip/close=%v tcc=%d op=%d",
			CROBIsTripClose(0x81), CROBTCC(0x81), CROBOpType(0x81))
	}
}

// TestExtractCROBs_LatchIsNotTripClose confirms LATCH_ON/OFF are not
// flagged as breaker trip/close.
func TestExtractCROBs_LatchIsNotTripClose(t *testing.T) {
	t.Parallel()
	if CROBIsTripClose(0x03) { // 0x03 = NUL TCC + LATCH_ON
		t.Fatal("LATCH_ON (0x03) wrongly flagged as trip/close")
	}
	if CROBOpType(0x03) != OpLatchOn {
		t.Fatalf("0x03 op = %d, want LATCH_ON %d", CROBOpType(0x03), OpLatchOn)
	}
}

// TestExtractCROBs_TwoOctetIndexPrefix covers qualifier 0x28.
func TestExtractCROBs_TwoOctetIndexPrefix(t *testing.T) {
	t.Parallel()
	apdu := []byte{GroupBinaryOutputControl, VarCROB, 0x28, 0x01, 0x00} // count=1 (LE)
	apdu = append(apdu, 0x02, 0x01)                                     // index 0x0102 (LE)
	apdu = append(apdu, crob(0x41)...)                                  // CLOSE + PULSE_ON
	points, ok := ExtractCROBs(apdu)
	if !ok || len(points) != 1 || points[0].Index != 0x0102 || points[0].ControlCode != 0x41 {
		t.Fatalf("ExtractCROBs = %v %+v, want ok=true {0x0102, 0x41}", ok, points)
	}
}

// TestExtractCROBs_NotACROB returns (nil, true) for a non-g12v1 first
// object: there is nothing to scope, not a parse error.
func TestExtractCROBs_NotACROB(t *testing.T) {
	t.Parallel()
	apdu := []byte{60, 1, 0x06} // g60v1 (Class 0 data), all-points qualifier
	points, ok := ExtractCROBs(apdu)
	if !ok || points != nil {
		t.Fatalf("ExtractCROBs on non-CROB = %v %v, want (nil, true)", points, ok)
	}
}

// TestExtractCROBs_TruncatedFailsClosed proves a truncated CROB is
// refused (ok=false) rather than read past its end.
func TestExtractCROBs_TruncatedFailsClosed(t *testing.T) {
	t.Parallel()
	// Claims count=1 but supplies only the index, no 11-byte CROB.
	apdu := []byte{GroupBinaryOutputControl, VarCROB, 0x17, 0x01, 0x05}
	if _, ok := ExtractCROBs(apdu); ok {
		t.Fatal("truncated CROB accepted; must fail closed")
	}
}

// TestExtractCROBs_UnsupportedQualifierFailsClosed proves a g12v1 with
// an all-points (0x06) qualifier is refused.
func TestExtractCROBs_UnsupportedQualifierFailsClosed(t *testing.T) {
	t.Parallel()
	apdu := []byte{GroupBinaryOutputControl, VarCROB, 0x06}
	if _, ok := ExtractCROBs(apdu); ok {
		t.Fatal("g12v1 with all-points qualifier accepted; must fail closed")
	}
}

// TestIsBroadcast covers the reserved broadcast range.
func TestIsBroadcast(t *testing.T) {
	t.Parallel()
	for _, d := range []uint16{0xFFFD, 0xFFFE, 0xFFFF} {
		if !IsBroadcast(d) {
			t.Errorf("0x%04X should be broadcast", d)
		}
	}
	for _, d := range []uint16{0x0000, 0x0001, 0x000A, 0xFFFC} {
		if IsBroadcast(d) {
			t.Errorf("0x%04X should not be broadcast", d)
		}
	}
}
