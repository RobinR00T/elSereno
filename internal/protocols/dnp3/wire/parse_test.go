package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

func TestParseHeader(t *testing.T) {
	t.Parallel()
	h, err := wire.ParseHeader(wire.BuildReadClass0(1, 2))
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Dest != 1 || h.Src != 2 {
		t.Fatalf("dest=%d src=%d", h.Dest, h.Src)
	}
}

func TestRejectsBadStart(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseHeader([]byte{0xFF, 0xFF, 0x05, 0xC4, 0, 0, 0, 0, 0, 0})
	if !errors.Is(err, wire.ErrBadStart) {
		t.Fatalf("got %v, want ErrBadStart", err)
	}
}
