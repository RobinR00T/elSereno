package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

// TestParseHeader_RealCapture validates the DNP3 link-layer header parser
// against real frames, byte for byte from CISA cisagov/icsnpp-dnp3
// testing/traces/dnp3_example.pcap.
func TestParseHeader_RealCapture(t *testing.T) {
	cases := []struct {
		name    string
		frame   string
		length  uint8
		control uint8
		dest    uint16
		src     uint16
		crc     uint16
	}{
		{"primary_confirmed", "05640bc4050064006f36", 0x0b, 0xc4, 5, 100, 0x366f},
		{"response_long", "0564ff44640005003518", 0xff, 0x44, 100, 5, 0x1835},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := hex.DecodeString(tc.frame)
			if err != nil {
				t.Fatal(err)
			}
			h, err := wire.ParseHeader(b)
			if err != nil {
				t.Fatalf("ParseHeader on a real frame: %v", err)
			}
			if h.Length != tc.length || h.Control != tc.control ||
				h.Dest != tc.dest || h.Src != tc.src || h.CRC != tc.crc {
				t.Errorf("header = %+v, want len=%d ctrl=0x%02x dest=%d src=%d crc=0x%04x",
					h, tc.length, tc.control, tc.dest, tc.src, tc.crc)
			}
		})
	}
}
