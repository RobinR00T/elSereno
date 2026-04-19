package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/bacnet/wire"
)

func TestParseBVLC(t *testing.T) {
	t.Parallel()
	b := wire.BuildWhoIs()
	h, err := wire.ParseBVLC(b)
	if err != nil {
		t.Fatalf("ParseBVLC: %v", err)
	}
	if h.Type != wire.BVLCTypeBacnetIP {
		t.Fatalf("Type=0x%02x", h.Type)
	}
}

func TestParseBVLCRejectsBadType(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseBVLC([]byte{0x00, 0x0A, 0x00, 0x04})
	if !errors.Is(err, wire.ErrBadBVLC) {
		t.Fatalf("got %v, want ErrBadBVLC", err)
	}
}

func TestIsIAm(t *testing.T) {
	t.Parallel()
	if !wire.IsIAm([]byte{0x10, 0x00, 0xC4}) {
		t.Fatal("IsIAm false for valid I-Am prefix")
	}
	if wire.IsIAm([]byte{0x10, 0x08}) {
		t.Fatal("IsIAm true for Who-Is")
	}
}
