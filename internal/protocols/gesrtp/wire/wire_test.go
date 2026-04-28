package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

func TestBuildConnectionInitLayout(t *testing.T) {
	t.Parallel()
	got := wire.BuildConnectionInit()
	if len(got) != 56 {
		t.Fatalf("frame length: got %d want 56", len(got))
	}
	if got[0] != 0x02 {
		t.Fatalf("type byte: got 0x%02x want 0x02", got[0])
	}
	for i := 1; i < len(got); i++ {
		if got[i] != 0x00 {
			t.Fatalf("byte %d: got 0x%02x want 0x00", i, got[i])
		}
	}
}

func TestClassifyResponseHappyPath(t *testing.T) {
	t.Parallel()
	resp := make([]byte, 56)
	resp[0] = 0x03
	if err := wire.ClassifyResponse(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClassifyResponseShortFrame(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 27, 55} {
		err := wire.ClassifyResponse(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestClassifyResponseWrongType(t *testing.T) {
	t.Parallel()
	for _, b := range []byte{0x00, 0x01, 0x02, 0x04, 0xFF} {
		resp := make([]byte, 56)
		resp[0] = b
		err := wire.ClassifyResponse(resp)
		if !errors.Is(err, wire.ErrNotResponse) {
			t.Fatalf("byte0=0x%02x: expected ErrNotResponse, got %v", b, err)
		}
	}
}

func TestClassifyResponseLongerThan56AcceptsPrefix(t *testing.T) {
	t.Parallel()
	// SRTP is mailbox-framed, but a TCP read could hand us extra
	// bytes from a follow-up frame. The classifier should accept
	// a response prefix as long as the first 56 bytes are valid.
	resp := make([]byte, 128)
	resp[0] = 0x03
	if err := wire.ClassifyResponse(resp); err != nil {
		t.Fatalf("unexpected error on prefixed response: %v", err)
	}
}

func TestIsMailboxResponseTrueOnly(t *testing.T) {
	t.Parallel()
	resp := make([]byte, 56)
	resp[0] = 0x03
	if !wire.IsMailboxResponse(resp) {
		t.Fatalf("expected true on a 56-byte 0x03 prefix")
	}
	req := wire.BuildConnectionInit()
	if wire.IsMailboxResponse(req) {
		t.Fatalf("expected false on a request frame")
	}
	if wire.IsMailboxResponse(nil) {
		t.Fatalf("nil should not be a mailbox response")
	}
	if wire.IsMailboxResponse([]byte{0x03}) {
		t.Fatalf("single byte too short to be a mailbox response")
	}
	short := make([]byte, 55)
	short[0] = 0x03
	if wire.IsMailboxResponse(short) {
		t.Fatalf("55-byte buffer too short")
	}
}
