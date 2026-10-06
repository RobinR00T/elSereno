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

// TestValidHeader_RealCapture checks the probe's classifier against real
// outstation and master headers from the same CISA capture (all carry a
// correct header CRC, which CRC16 must reproduce) and rejects each one
// with a single CRC octet flipped.
func TestValidHeader_RealCapture(t *testing.T) {
	for _, frame := range []string{
		"05640bc4050064006f36", // master Read Class 0
		"056418c405006400fedd", // master request
		"0564ff44640005003518", // outstation response
	} {
		b, err := hex.DecodeString(frame)
		if err != nil {
			t.Fatal(err)
		}
		if !wire.ValidHeader(b) {
			t.Errorf("ValidHeader(%s) = false on a real frame", frame)
		}
		b[9] ^= 0x01
		if wire.ValidHeader(b) {
			t.Errorf("ValidHeader(%s with a corrupt CRC) = true", frame)
		}
	}
}

// TestBuildRequestLinkStatus_NSEReference validates the probe request
// byte for byte against nmap's dnp3-info.nse (DigitalBond Redpoint),
// which sends these Request Link Status frames from master address 0.
// The capture's master Read Class 0 is the reference for the CRC itself
// (TestValidHeader_RealCapture). PITF-073: the previous request was a
// 5-octet header with a zero CRC, which an outstation discards.
func TestBuildRequestLinkStatus_NSEReference(t *testing.T) {
	nse := map[uint16]string{ // destination -> frame, from the NSE's first100
		0x00: "056405c900000000364c",
		0x01: "056405c901000000de8e",
		0x02: "056405c9020000009f84",
		0x3c: "056405c93c00000022c1",
		0x3e: "056405c93e0000008b09",
		0x63: "056405c9630000002e43",
		0x64: "056405c9640000004495",
	}
	for dest, want := range nse {
		if got := hex.EncodeToString(wire.BuildRequestLinkStatus(dest, 0)); got != want {
			t.Errorf("BuildRequestLinkStatus(0x%02x, 0) = %s, want %s", dest, got, want)
		}
	}
}

// TestBuildLinkStatusSweep covers every destination 0..SweepLastDest,
// in order, each frame a valid Request Link Status from src.
func TestBuildLinkStatusSweep(t *testing.T) {
	const src = 0
	s := wire.BuildLinkStatusSweep(src, wire.SweepLastDest)
	if len(s) != (wire.SweepLastDest+1)*wire.HeaderLen {
		t.Fatalf("sweep length %d, want %d", len(s), (wire.SweepLastDest+1)*wire.HeaderLen)
	}
	for dest := 0; dest <= wire.SweepLastDest; dest++ {
		f := s[dest*wire.HeaderLen : (dest+1)*wire.HeaderLen]
		h, err := wire.ParseHeader(f)
		if err != nil || !wire.ValidHeader(f) {
			t.Fatalf("frame %d invalid: %x (%v)", dest, f, err)
		}
		if int(h.Dest) != dest || h.Src != src || h.Control != wire.RequestLinkStatusControl || h.Length != 5 {
			t.Fatalf("frame %d = %+v", dest, h)
		}
	}
}
