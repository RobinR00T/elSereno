package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/iec104/wire"
)

func TestParseAPCI(t *testing.T) {
	t.Parallel()
	apci, err := wire.ParseAPCI(wire.BuildTESTFR())
	if err != nil {
		t.Fatalf("ParseAPCI: %v", err)
	}
	if apci.Type() != wire.FrameU {
		t.Fatalf("Type=%s", apci.Type())
	}
}

func TestRejectsBadStart(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseAPCI([]byte{0xFF, 0x04, 0x43, 0, 0, 0})
	if !errors.Is(err, wire.ErrBadStart) {
		t.Fatalf("got %v", err)
	}
}
