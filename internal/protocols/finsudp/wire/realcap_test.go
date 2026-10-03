package wire_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/finsudp/wire"
)

// TestParseControllerDataRead_RealCapture validates ParseControllerDataRead
// against a real FINS CONTROLLER DATA READ response (byte for byte from CISA
// cisagov/icsnpp-omron-fins omron_test.pcap): an Omron CP1L-EL20DR-D PLC.
// This exercises the field layout on real wire, where the reserved
// "For System Use" area that an earlier version mis-read as a version string
// (PITF-065) actually carries non-version bytes.
func TestParseControllerDataRead_RealCapture(t *testing.T) {
	// FINS/UDP frame (UDP payload = FINS frame). SID = 0xEF.
	frame, err := hex.DecodeString(
		"c0000200630000c800ef050100004350314c2d454c323044522d440000002020202030312e3030000000000030312e3036000000000000000000000000000000000000000000000000010000000000000000000000000000000000010003000a172a1008000000000000")
	if err != nil {
		t.Fatal(err)
	}
	cd, err := wire.ParseControllerDataRead(frame, 0xEF)
	if err != nil {
		t.Fatalf("ParseControllerDataRead on a real CP1L reply: %v", err)
	}
	if cd.Model != "CP1L-EL20DR-D" {
		t.Errorf("Model = %q, want CP1L-EL20DR-D", cd.Model)
	}
	// Controller Version packs two sub-versions ("01.00" and "01.06") in the
	// 20-byte field; both must survive.
	if !strings.Contains(cd.InternalCode, "01.00") || !strings.Contains(cd.InternalCode, "01.06") {
		t.Errorf("InternalCode = %q, want it to contain 01.00 and 01.06", cd.InternalCode)
	}
}
