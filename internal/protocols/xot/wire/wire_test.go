package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/xot/wire"
)

func TestHeaderRoundTrip(t *testing.T) {
	t.Parallel()
	h := wire.Header{Version: wire.Version, Length: 42}
	b := wire.MarshalHeader(h)
	got, err := wire.ParseHeader(b[:])
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got != h {
		t.Fatalf("round-trip: got %+v, want %+v", got, h)
	}
}

func TestHeaderRejectsBadVersion(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseHeader([]byte{0xde, 0xad, 0x00, 0x05})
	if !errors.Is(err, wire.ErrBadVersion) {
		t.Fatalf("got %v, want ErrBadVersion", err)
	}
}

func TestHeaderRejectsOversizedLength(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseHeader([]byte{0x00, 0x00, 0xff, 0xff}) // 65535
	if !errors.Is(err, wire.ErrPayloadTooLong) {
		t.Fatalf("got %v, want ErrPayloadTooLong", err)
	}
}

func TestHeaderRejectsShortLength(t *testing.T) {
	t.Parallel()
	_, err := wire.ParseHeader([]byte{0x00, 0x00, 0x00, 0x01})
	if !errors.Is(err, wire.ErrPayloadTooShort) {
		t.Fatalf("got %v, want ErrPayloadTooShort", err)
	}
}

func TestParseX25CallRequest(t *testing.T) {
	t.Parallel()
	buf := wire.MarshalCallRequest(17)
	p, err := wire.ParseX25(buf)
	if err != nil {
		t.Fatalf("ParseX25: %v", err)
	}
	if p.Type != wire.PacketCallRequest {
		t.Fatalf("Type=%s, want CALL_REQUEST", p.Type)
	}
	if p.LCN != 17 {
		t.Fatalf("LCN=%d, want 17", p.LCN)
	}
}

func TestParseX25Clear(t *testing.T) {
	t.Parallel()
	p, err := wire.ParseX25([]byte{0x10, 0x01, uint8(wire.PacketClearRequest), 0x05, 0x00})
	if err != nil {
		t.Fatalf("ParseX25: %v", err)
	}
	cause, diag, ok := wire.ClearCause(p)
	if !ok || cause != 0x05 || diag != 0x00 {
		t.Fatalf("ClearCause = %d,%d,%v; want 5,0,true", cause, diag, ok)
	}
}

func TestDataPacketCollapse(t *testing.T) {
	t.Parallel()
	p, err := wire.ParseX25([]byte{0x10, 0x01, 0x00, 0xaa, 0xbb})
	if err != nil {
		t.Fatalf("ParseX25: %v", err)
	}
	if p.Type != wire.PacketData {
		t.Fatalf("Type=%s, want DATA", p.Type)
	}
}

func TestWriteReadFrameRoundTrip(t *testing.T) {
	t.Parallel()
	payload := wire.MarshalCallRequest(42)
	var buf bytes.Buffer
	if err := wire.WriteXOTFrame(&buf, payload); err != nil {
		t.Fatalf("WriteXOTFrame: %v", err)
	}
	p, err := wire.ReadXOTFrame(&buf)
	if err != nil {
		t.Fatalf("ReadXOTFrame: %v", err)
	}
	if p.Type != wire.PacketCallRequest {
		t.Fatalf("Type=%s, want CALL_REQUEST", p.Type)
	}
	if p.LCN != 42 {
		t.Fatalf("LCN=%d, want 42", p.LCN)
	}
}
