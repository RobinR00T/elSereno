package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/iax2/wire"
)

func TestBuildNEW_Roundtrip(t *testing.T) {
	raw := wire.BuildNEW(0x1234)
	if len(raw) != wire.HeaderLen {
		t.Fatalf("NEW frame size = %d, want %d", len(raw), wire.HeaderLen)
	}
	h, err := wire.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.SrcCallNum != 0x1234 {
		t.Fatalf("SrcCallNum = 0x%04x, want 0x1234", h.SrcCallNum)
	}
	if h.DstCallNum != 0 {
		t.Fatalf("DstCallNum = %d, want 0", h.DstCallNum)
	}
	if h.FrameType != wire.FrameTypeIAX {
		t.Fatalf("FrameType = %d, want IAX (0x06)", h.FrameType)
	}
	if h.Subclass != byte(wire.IAXNew) {
		t.Fatalf("Subclass = 0x%02x, want NEW (0x01)", h.Subclass)
	}
	if !h.IsIAXReply() {
		t.Fatalf("IsIAXReply() = false, want true")
	}
}

func TestParseHeader_RejectsMiniFrame(t *testing.T) {
	// A mini-frame has the high bit of byte 0 unset.
	b := []byte{0x00, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x00, 0, 0, 0, 0}
	_, err := wire.ParseHeader(b)
	if !errors.Is(err, wire.ErrMiniFrame) {
		t.Fatalf("want ErrMiniFrame, got %v", err)
	}
}

func TestParseHeader_RejectsShort(t *testing.T) {
	_, err := wire.ParseHeader([]byte{0x80, 0x00})
	if !errors.Is(err, wire.ErrTooShort) {
		t.Fatalf("want ErrTooShort, got %v", err)
	}
}

func TestBuildHANGUP(t *testing.T) {
	raw := wire.BuildHANGUP(0xABCD, 0x1111, 1, 2)
	h, err := wire.ParseHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.SrcCallNum != 0xABCD&0x7FFF {
		t.Fatalf("SrcCallNum = 0x%04x", h.SrcCallNum)
	}
	if h.DstCallNum != 0x1111 {
		t.Fatalf("DstCallNum = 0x%04x", h.DstCallNum)
	}
	if h.OSeqno != 1 || h.ISeqno != 2 {
		t.Fatalf("sequences = %d/%d", h.OSeqno, h.ISeqno)
	}
	if h.Subclass != byte(wire.IAXHangup) {
		t.Fatalf("subclass = 0x%02x, want HANGUP (0x05)", h.Subclass)
	}
}
