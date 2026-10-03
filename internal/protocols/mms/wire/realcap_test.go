package wire

import (
	"encoding/hex"
	"testing"
)

// TestACSEAssociateResponse_RealCapture validates the MMS ACSE association-
// response path against a real IEC 61850 MMS session, byte for byte from
// w3h/icsmaster pcap/IEC61850/MMS/iec61850_read.pcap (a libIEC61850-style
// server). The value is the full TPKT payload of the server's AARE packet
// (COTP DT + ISO session + presentation + ACSE AARE), exactly what the mms
// probe passes to ParseACSEAssociateResponseMMS.
//
// This capture is a generic simulator with no vendor marker, so the vendor
// hint is correctly empty; the positive vendor-finding path is still only
// fixture-exercised (the curated markers in mms_services.go).
func TestACSEAssociateResponse_RealCapture(t *testing.T) {
	payload, err := hex.DecodeString("02f0800e89050613010006010214020002c1003178a003800100a271830400000001a512300780010081025201300780010081025101880206006151304f020101a04a614880020780a107060528ca220203a203020100a305a103020100a40606042bce0f02a503020117be20281e020103a019a917800100810100820100830100a409800100810100820100")
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseACSEAssociateResponseMMS(payload); err != nil {
		t.Fatalf("ParseACSEAssociateResponseMMS rejected a real AARE: %v", err)
	}
	// No curated vendor marker in this generic capture: the hint is empty,
	// not a false positive.
	if hint := ExtractMMSVendorHint(payload); hint != "" {
		t.Errorf("vendor hint = %q, want empty for a marker-less capture", hint)
	}
}
