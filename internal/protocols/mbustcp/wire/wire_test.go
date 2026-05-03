package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/mbustcp/wire"
)

func TestBuildREQUD2Layout(t *testing.T) {
	t.Parallel()
	got := wire.BuildREQUD2(0xFE)
	want := []byte{0x10, 0x5B, 0xFE, 0x59, 0x16}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame: got %x want %x", got, want)
	}
}

func TestBuildREQUD2ChecksumPerAddress(t *testing.T) {
	t.Parallel()
	for _, addr := range []byte{0x00, 0x01, 0x7F, 0xFD, 0xFE} {
		got := wire.BuildREQUD2(addr)
		expectedCS := byte(0x5B) + addr
		if got[3] != expectedCS {
			t.Fatalf("addr=0x%02x: checksum got 0x%02x want 0x%02x", addr, got[3], expectedCS)
		}
	}
}

func TestParseRSPUDSuccess(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x12345678, "KAM", 0x12, 0x07) // Kamstrup water meter
	mi, err := wire.ParseRSPUD(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mi.ID != 0x12345678 {
		t.Fatalf("ID: got 0x%08x", mi.ID)
	}
	if mi.Manufacturer != "KAM" {
		t.Fatalf("Manufacturer: got %q", mi.Manufacturer)
	}
	if mi.Version != 0x12 {
		t.Fatalf("Version: got 0x%02x", mi.Version)
	}
	if mi.Medium != 0x07 {
		t.Fatalf("Medium: got 0x%02x", mi.Medium)
	}
}

func TestParseRSPUDDecodesABB(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	mi, err := wire.ParseRSPUD(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mi.Manufacturer != "ABB" {
		t.Fatalf("ABB: got %q", mi.Manufacturer)
	}
}

func TestParseRSPUDShortFrame(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 5, 12, 18} {
		_, err := wire.ParseRSPUD(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestParseRSPUDBadStart(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	frame[0] = 0x10 // short-frame start
	_, err := wire.ParseRSPUD(frame)
	if !errors.Is(err, wire.ErrBadStart) {
		t.Fatalf("expected ErrBadStart, got %v", err)
	}
}

func TestParseRSPUDLengthMismatch(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	frame[1]++ // make L1 != L2
	_, err := wire.ParseRSPUD(frame)
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("expected ErrLengthMismatch on L1 != L2, got %v", err)
	}
}

func TestParseRSPUDBadStop(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	frame[len(frame)-1] = 0x00 // not 0x16
	_, err := wire.ParseRSPUD(frame)
	if !errors.Is(err, wire.ErrBadStop) {
		t.Fatalf("expected ErrBadStop, got %v", err)
	}
}

func TestParseRSPUDChecksumMismatch(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	frame[len(frame)-2] ^= 0xFF // flip the checksum
	_, err := wire.ParseRSPUD(frame)
	if !errors.Is(err, wire.ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestParseRSPUDNotVarData(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	frame[6] = 0x73 // not 0x72
	// Recompute checksum.
	var cs byte
	for i := 4; i < len(frame)-2; i++ {
		cs += frame[i]
	}
	frame[len(frame)-2] = cs
	_, err := wire.ParseRSPUD(frame)
	if !errors.Is(err, wire.ErrNotVarDataResponse) {
		t.Fatalf("expected ErrNotVarDataResponse, got %v", err)
	}
}

func TestIsRSPUDClassification(t *testing.T) {
	t.Parallel()
	frame := buildRSPUD(0x00000001, "ABB", 0x01, 0x02)
	if !wire.IsRSPUD(frame) {
		t.Fatalf("expected true on a real RSP_UD")
	}
	short := wire.BuildREQUD2(0x01)
	if wire.IsRSPUD(short) {
		t.Fatalf("expected false on a short-frame request")
	}
	if wire.IsRSPUD(nil) || wire.IsRSPUD([]byte{0x68}) {
		t.Fatalf("nil / 1-byte buffers should not classify as RSP_UD")
	}
}

func TestIsACK(t *testing.T) {
	t.Parallel()
	if !wire.IsACK([]byte{0xE5}) {
		t.Fatalf("expected true on single-byte 0xE5")
	}
	if wire.IsACK([]byte{0xE5, 0x00}) {
		t.Fatalf("multi-byte buffer should not be ACK")
	}
	if wire.IsACK(nil) || wire.IsACK([]byte{0x10}) {
		t.Fatalf("nil / wrong byte should not classify as ACK")
	}
}

// buildRSPUD produces a complete RSP_UD long frame with the
// given fields. UD is 11 bytes (CI + ID(4) + Manuf(2) + Ver +
// Medium + AccessNo + Status). With Signature(2) that's 13.
// The shift+truncate byte extractions below are the canonical Go
// idiom for wire-frame synthesis (gosec G115 noise).
//
// #nosec G115 -- false positives on byte extractions.
func buildRSPUD(id uint32, manuf string, version, medium byte) []byte {
	if len(manuf) != 3 {
		panic("buildRSPUD: manuf must be 3 letters")
	}
	manufID := uint16(0)
	manufID |= uint16(manuf[0]-'A'+1) << 10
	manufID |= uint16(manuf[1]-'A'+1) << 5
	manufID |= uint16(manuf[2] - 'A' + 1)

	body := []byte{
		0x08, // C: RSP_UD
		0x01, // A: address
		0x72, // CI: variable data response
		byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24),
		byte(manufID), byte(manufID >> 8),
		version,
		medium,
		0x00,       // Access No
		0x00,       // Status
		0x00, 0x00, // Signature
	}
	declaredLen := byte(len(body))
	frame := []byte{0x68, declaredLen, declaredLen, 0x68}
	frame = append(frame, body...)
	var cs byte
	for _, b := range body {
		cs += b
	}
	frame = append(frame, cs, 0x16)
	return frame
}
