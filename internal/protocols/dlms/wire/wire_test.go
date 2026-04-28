package wire_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/dlms/wire"
)

func TestBuildAARQLayout(t *testing.T) {
	t.Parallel()
	got := wire.BuildAARQ()
	if len(got) != 8+29 {
		t.Fatalf("frame length: got %d want 37", len(got))
	}
	if binary.BigEndian.Uint16(got[0:2]) != 0x0001 {
		t.Fatalf("wrapper version: got 0x%04x", binary.BigEndian.Uint16(got[0:2]))
	}
	if binary.BigEndian.Uint16(got[2:4]) != 0x0010 {
		t.Fatalf("source wPort: got 0x%04x", binary.BigEndian.Uint16(got[2:4]))
	}
	if binary.BigEndian.Uint16(got[4:6]) != 0x0001 {
		t.Fatalf("dest wPort: got 0x%04x", binary.BigEndian.Uint16(got[4:6]))
	}
	if binary.BigEndian.Uint16(got[6:8]) != 29 {
		t.Fatalf("apdu length: got %d", binary.BigEndian.Uint16(got[6:8]))
	}
	if got[8] != 0x60 {
		t.Fatalf("AARQ tag: got 0x%02x", got[8])
	}
}

func TestClassifyResponseHappyPath(t *testing.T) {
	t.Parallel()
	resp := buildAARE()
	info, err := wire.ClassifyResponse(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.SourceWPort != 0x0001 {
		t.Fatalf("SourceWPort: got 0x%04x", info.SourceWPort)
	}
	if info.DestWPort != 0x0010 {
		t.Fatalf("DestWPort: got 0x%04x", info.DestWPort)
	}
	if info.APDULen != 20 {
		t.Fatalf("APDULen: got %d", info.APDULen)
	}
}

func TestClassifyResponseShortFrame(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 4, 8} {
		_, err := wire.ClassifyResponse(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestClassifyResponseBadWrapperVersion(t *testing.T) {
	t.Parallel()
	resp := buildAARE()
	binary.BigEndian.PutUint16(resp[0:2], 0x0002)
	_, err := wire.ClassifyResponse(resp)
	if !errors.Is(err, wire.ErrBadWrapperVersion) {
		t.Fatalf("expected ErrBadWrapperVersion, got %v", err)
	}
}

func TestClassifyResponseLengthMismatch(t *testing.T) {
	t.Parallel()
	resp := buildAARE()
	binary.BigEndian.PutUint16(resp[6:8], 0xFF00)
	_, err := wire.ClassifyResponse(resp)
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("expected ErrLengthMismatch, got %v", err)
	}
}

func TestClassifyResponseNotAARE(t *testing.T) {
	t.Parallel()
	resp := buildAARE()
	resp[8] = 0x60 // AARQ tag, not AARE
	_, err := wire.ClassifyResponse(resp)
	if !errors.Is(err, wire.ErrNotAARE) {
		t.Fatalf("expected ErrNotAARE, got %v", err)
	}
}

func TestIsWrapperResponse(t *testing.T) {
	t.Parallel()
	resp := buildAARE()
	if !wire.IsWrapperResponse(resp) {
		t.Fatalf("expected true on valid wrapper")
	}
	short := make([]byte, 7)
	if wire.IsWrapperResponse(short) {
		t.Fatalf("7-byte buffer too short")
	}
	wrong := make([]byte, 8)
	if wire.IsWrapperResponse(wrong) {
		t.Fatalf("zero version should not classify as wrapper")
	}
	if wire.IsWrapperResponse(nil) {
		t.Fatalf("nil should not classify as wrapper")
	}
}

// buildAARE produces a 28-byte AARE frame: 8-byte wrapper +
// 20-byte zero-padded APDU starting with the AARE tag (0x61).
// The successful-classification tests don't introspect APDU
// content beyond the tag — they verify wrapper consistency.
func buildAARE() []byte {
	const apduLen = 20
	frame := make([]byte, 8+apduLen)
	binary.BigEndian.PutUint16(frame[0:2], 0x0001)
	binary.BigEndian.PutUint16(frame[2:4], 0x0001) // server src
	binary.BigEndian.PutUint16(frame[4:6], 0x0010) // dest = client
	binary.BigEndian.PutUint16(frame[6:8], apduLen)
	frame[8] = 0x61 // AARE-PDU tag
	return frame
}
