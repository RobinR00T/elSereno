package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/xot/wire"
)

// FuzzParseHeader asserts that ParseHeader never panics, and on
// success produces a Length within [MinPayloadLen, MaxPayloadLen] and
// Version==0.
func FuzzParseHeader(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x03})
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef})
	f.Add([]byte{0x00, 0x00, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := wire.ParseHeader(b)
		if err != nil {
			return
		}
		if h.Version != wire.Version {
			t.Fatalf("Version=%d, want %d", h.Version, wire.Version)
		}
		if h.Length < wire.MinPayloadLen || h.Length > wire.MaxPayloadLen {
			t.Fatalf("Length=%d out of range", h.Length)
		}
	})
}

// FuzzParseX25 asserts that ParseX25 never panics and that, on
// success, it returns a valid Packet whose LCN fits 12 bits.
func FuzzParseX25(f *testing.F) {
	f.Add(wire.MarshalCallRequest(0))
	f.Add(wire.MarshalCallRequest(4095))
	f.Add([]byte{0x10, 0x01, uint8(wire.PacketClearRequest), 0x05, 0x00})
	f.Add([]byte{0x10, 0x01, 0x00, 0xaa, 0xbb})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := wire.ParseX25(b)
		if err != nil {
			return
		}
		if p.LCN > 0x0fff {
			t.Fatalf("LCN=%d exceeds 12 bits", p.LCN)
		}
		if len(p.Payload) > wire.MaxPayloadLen {
			t.Fatalf("Payload=%d > max", len(p.Payload))
		}
	})
}

// FuzzFrameRoundTrip asserts that for any inner X.25 buffer in the
// valid range, a written frame reads back with the same PTI.
func FuzzFrameRoundTrip(f *testing.F) {
	f.Add([]byte{0x10, 0x01, uint8(wire.PacketCallRequest), 0x00, 0x00})
	f.Add([]byte{0x10, 0x01, uint8(wire.PacketClearRequest), 0x05, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < wire.MinPayloadLen || len(b) > wire.MaxPayloadLen {
			return
		}
		var buf bytes.Buffer
		if err := wire.WriteXOTFrame(&buf, b); err != nil {
			t.Fatalf("WriteXOTFrame: %v", err)
		}
		p, err := wire.ReadXOTFrame(&buf)
		if err != nil {
			t.Fatalf("ReadXOTFrame: %v", err)
		}
		if p.PTI != b[2] {
			t.Fatalf("PTI mismatch: got %x, want %x", p.PTI, b[2])
		}
	})
}
