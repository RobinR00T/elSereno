package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/iax2/wire"
)

// realNEW is the IAX2 payload of a real incoming NEW full frame, taken
// verbatim from the UDP payload of packet 1 of the Wireshark
// SampleCaptures capture "IAX2_incoming_call" (212.29.199.163:4569 ->
// 192.168.2.100:4569). It is an actual call-setup frame from an Asterisk
// peer, not a hand-built fixture: it carries the real IE block (VERSION=2,
// CALLED/CALLING NUMBER, USERNAME "ranshe", LANGUAGE "en", FORMAT,
// CAPABILITY, ADSICPE, DATETIME).
//
// Header bytes 0..11 decode as: F=1 (full frame), SrcCallNum=498,
// DstCallNum=0 (NEW has no callee number yet), Timestamp=10, OSeqno=0,
// ISeqno=0, FrameType=0x06 (IAX), Subclass=0x01 (NEW).
const realNEW = "81f200000000000a000006010b020002010173020930333937373332313104093033393737333231310a02656e060672616e73686509040000000208040000f8020c0200021f040c36b090"

// TestParseHeader_RealNEW validates the full-frame header parser against a
// real IAX2 NEW frame byte for byte. This is the "real capture" leg of the
// parser-validation matrix for IAX2: it confirms the field offsets (the
// F-bit position, the 15-bit call-number masks, the big-endian timestamp,
// and the FrameType/Subclass bytes) agree with what an Asterisk peer
// actually puts on the wire, not merely with the parser's own fixtures.
func TestParseHeader_RealNEW(t *testing.T) {
	frame, err := hex.DecodeString(realNEW)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) < wire.HeaderLen {
		t.Fatalf("real NEW frame length = %d, want >= %d", len(frame), wire.HeaderLen)
	}

	h, err := wire.ParseHeader(frame)
	if err != nil {
		t.Fatalf("ParseHeader rejected a real IAX2 NEW frame: %v", err)
	}

	cases := []struct {
		name      string
		got, want uint32
	}{
		{"SrcCallNum", uint32(h.SrcCallNum), 498},
		{"DstCallNum", uint32(h.DstCallNum), 0},
		{"Timestamp", h.Timestamp, 10},
		{"OSeqno", uint32(h.OSeqno), 0},
		{"ISeqno", uint32(h.ISeqno), 0},
		{"FrameType", uint32(h.FrameType), uint32(wire.FrameTypeIAX)},
		{"Subclass", uint32(h.Subclass), uint32(wire.IAXNew)},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	if !h.IsIAXReply() {
		t.Error("IsIAXReply() = false for a real IAX-class frame")
	}
}

// TestBuildNEW_MatchesRealFrameShape confirms the NEW frame the probe sends
// has the same classifying shape as the real captured NEW: full-frame bit
// set, DstCallNum 0, sequence numbers 0, FrameType IAX, Subclass NEW. Only
// the SrcCallNum (randomised per probe) and the Timestamp differ, so those
// are excluded from the comparison.
func TestBuildNEW_MatchesRealFrameShape(t *testing.T) {
	realFrame, err := hex.DecodeString(realNEW)
	if err != nil {
		t.Fatal(err)
	}
	built := wire.BuildNEW(0x01f2) // same SrcCallNum as the capture, for a byte-level header compare

	// Full-frame bit (high bit of byte 0).
	if built[0]&0x80 != realFrame[0]&0x80 {
		t.Errorf("F bit: built 0x%02x, real 0x%02x", built[0]&0x80, realFrame[0]&0x80)
	}
	// DstCallNum (bytes 2-3) is 0 on a NEW in both.
	if built[2] != realFrame[2] || built[3] != realFrame[3] {
		t.Errorf("DstCallNum bytes: built %02x%02x, real %02x%02x", built[2], built[3], realFrame[2], realFrame[3])
	}
	// OSeqno/ISeqno and FrameType/Subclass must match the real frame.
	for _, off := range []int{8, 9, 10, 11} {
		if built[off] != realFrame[off] {
			t.Errorf("byte %d: built 0x%02x, real 0x%02x", off, built[off], realFrame[off])
		}
	}
	// The SrcCallNum we asked for must round-trip through ParseHeader.
	h, err := wire.ParseHeader(built)
	if err != nil {
		t.Fatalf("ParseHeader(built) error: %v", err)
	}
	if h.SrcCallNum != 0x01f2 {
		t.Errorf("built SrcCallNum = %d, want %d", h.SrcCallNum, 0x01f2)
	}
}
