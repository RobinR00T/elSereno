package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/mbustcp/wire"
)

// realRSPUD is a real M-Bus RSP_UD long-frame response from an Itron / ACW
// (Actaris) CYBLE M-Bus water meter, taken verbatim from the rscada/libmbus
// test corpus (test/test-frames/ACW_Itron-CYBLE-M-Bus-14.hex), whose
// expected decode (ACW_Itron-CYBLE-M-Bus-14.xml) is Id 9011523,
// Manufacturer "ACW", Version 20, Medium Water. This is a frame a real
// meter put on the wire, not a hand-built fixture, so it validates the
// variable-data-header parse (ID / manufacturer / version / medium offsets)
// and the long-frame length + checksum checks on real bytes.
//
// M-Bus over TCP carries the same application-layer telegram as the serial
// bus, so the libmbus serial frame is exactly what the mbustcp parser
// consumes.
const realRSPUD = "685656680801722315010977041407250000000c78231501090d7c08" +
	"4449202e747375630a353537363730414c3930046d1a0ecd13027c09656d" +
	"6974202e746162d40904131f00000004937f0000000044131f0000000f00" +
	"011fa916"

// TestParseRSPUD_RealMeter validates the M-Bus RSP_UD parser against a real
// meter frame byte for byte: the 0x68 L L 0x68 long-frame framing, the
// length and checksum checks, and the variable-data-header fields
// (ID, manufacturer, version, medium). This is the "real capture" leg of the
// parser-validation matrix for M-Bus/TCP.
func TestParseRSPUD_RealMeter(t *testing.T) {
	buf, err := hex.DecodeString(realRSPUD)
	if err != nil {
		t.Fatal(err)
	}

	info, perr := wire.ParseRSPUD(buf)
	if perr != nil {
		t.Fatalf("ParseRSPUD rejected a real meter frame: %v", perr)
	}
	if info.ID != 0x09011523 {
		t.Errorf("ID = 0x%08x, want 0x09011523 (BCD 9011523)", info.ID)
	}
	if info.Manufacturer != "ACW" {
		t.Errorf("Manufacturer = %q, want %q", info.Manufacturer, "ACW")
	}
	if info.Version != 20 {
		t.Errorf("Version = %d, want 20", info.Version)
	}
	if info.Medium != 0x07 {
		t.Errorf("Medium = 0x%02x, want 0x07 (Water)", info.Medium)
	}
}
