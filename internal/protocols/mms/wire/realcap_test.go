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

// TestBuildACSEAssociateRequestMMS_RealCapture validates the probe's
// AARQ, not only the AARE parser (PITF-077): it is byte for byte the
// client AARQ of w3h/icsmaster iec61850_get_name_list.pcap and
// iec61850_read.pcap (the TPKT payload past the COTP DT header), which
// carries the MMS Initiate-RequestPDU the previous AARQ lacked.
func TestBuildACSEAssociateRequestMMS_RealCapture(t *testing.T) {
	const captured = "0db20506130100160102140200023302000134020001c19c318199a003800101a28191810400000001820400000001a423300f0201010604520100013004060251013010020103060528ca22020130040602510188020600615a3058020101a053605180020780a107060528ca220203a20606042bce0f02a303020117be35283306025101020103a02aa82880027530810203e8820203e8830105a417800101810305fb00820d03ffffffffffffffffffffff00"
	if got := hex.EncodeToString(BuildACSEAssociateRequestMMS()); got != captured {
		t.Fatalf("AARQ:\n got  %s\n want %s", got, captured)
	}
}

// TestGetNameList_RealCapture: with the capture's invoke ID (0) and
// object class (0, named variables), the wrapped getNameList we send is
// byte for byte the client's in iec61850_get_name_list.pcap (TPKT
// payload past the COTP DT header): session Give-Tokens + Data,
// presentation P-DATA on context 3, then the PDU with a vmd-specific
// NULL scope. The previous request had neither the wrapping nor a valid
// NULL.
func TestGetNameList_RealCapture(t *testing.T) {
	const captured = "0100010061173015020103a010a00e020100a109a003800100a1028000"
	if got := hex.EncodeToString(WrapPData(BuildMMSGetNameListRequest(0, ObjectClassNamedVariable))); got != captured {
		t.Fatalf("wrapped getNameList:\n got  %s\n want %s", got, captured)
	}
}

// TestUnwrapPData_RealCapture strips the session + presentation layers
// from the server's real replies in the same captures, and refuses a
// bare PDU (what the old probe expected) and a truncated frame.
func TestUnwrapPData_RealCapture(t *testing.T) {
	reply, err := hex.DecodeString("01000100610c300a020103a005a103020100")
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := UnwrapPData(reply)
	if err != nil {
		t.Fatalf("UnwrapPData on a real reply: %v", err)
	}
	if hex.EncodeToString(pdu) != "a103020100" {
		t.Fatalf("pdu = %x, want a103020100 (confirmed-ResponsePDU, invokeID 0)", pdu)
	}
	if _, err := UnwrapPData(pdu); err == nil {
		t.Error("a bare PDU unwrapped without error")
	}
	if _, err := UnwrapPData(reply[:len(reply)-1]); err == nil {
		t.Error("a truncated P-DATA unwrapped without error")
	}
	// Round trip with a long-form length.
	long := make([]byte, 200)
	long[0] = 0xA1
	got, err := UnwrapPData(WrapPData(long))
	if err != nil || len(got) != len(long) {
		t.Fatalf("round trip of a %d-octet PDU: len %d err %v", len(long), len(got), err)
	}
}
