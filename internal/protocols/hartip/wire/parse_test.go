package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/hartip/wire"
)

func TestParseHeader(t *testing.T) {
	t.Parallel()
	b := wire.BuildSessionInitiate(0x0001)
	h, err := wire.ParseHeader(b)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.MsgID != wire.IDSessionInitiate {
		t.Fatalf("MsgID=%d", h.MsgID)
	}
}

func TestRejectsBadVersion(t *testing.T) {
	t.Parallel()
	b := make([]byte, 8)
	b[0] = 0xFF
	_, err := wire.ParseHeader(b)
	if !errors.Is(err, wire.ErrBadHeader) {
		t.Fatalf("got %v", err)
	}
}
