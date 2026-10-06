package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/dlms/wire"
)

// TestClassifyResponse_RealCapture validates the DLMS/COSEM TCP-wrapper
// classifier against a real AARE (association response), byte for byte from
// zeus8497/dlms-analysis pcap-examples/dlms.pcap (DLMS over the IEC 62056-47
// TCP wrapper). Wrapper: version 0x0001, src/dst wport, length; then the
// ACSE AARE APDU (tag 0x61). This is the TCP-wrapper variant the elSereno
// probe fingerprints, distinct from the DLMS-over-HDLC captures.
func TestClassifyResponse_RealCapture(t *testing.T) {
	buf, err := hex.DecodeString("000100010001002b6129a109060760857405080101a203020100a305a103020101be10040e0800065f1f0400003a1d00720007")
	if err != nil {
		t.Fatal(err)
	}
	info, err := wire.ClassifyResponse(buf)
	if err != nil {
		t.Fatalf("ClassifyResponse rejected a real DLMS AARE: %v", err)
	}
	if info.APDULen != 43 {
		t.Errorf("APDULen = %d, want 43 (len %d minus the 8-byte wrapper)", info.APDULen, len(buf))
	}
	if info.SourceWPort != 1 || info.DestWPort != 1 {
		t.Errorf("wports = %d/%d, want 1/1", info.SourceWPort, info.DestWPort)
	}
}

// TestBuildAARQ_Reference validates the probe request (PITF-075). The
// APDU is byte for byte the public-client AARQ the Gurux DLMS client
// sends (gurux.fi forum node 19195). Its InitiateRequest must also have
// the layout of the one in the real zeus8497/dlms-analysis AARQ: tag
// 0x01, three omitted optionals, version 6, the 5F 1F 04 00 conformance
// header, three conformance octets and the 2-octet
// client-max-receive-pdu-size (FF FF there). Only the conformance bits
// may differ. The previous AARQ lacked the last field, which the Green
// Book's InitiateRequest makes mandatory.
func TestBuildAARQ_Reference(t *testing.T) {
	gurux, err := hex.DecodeString("601da109060760857405080101be10040e01000000065f1f0400001e5dffff")
	if err != nil {
		t.Fatal(err)
	}
	frame := wire.BuildAARQ()
	if got := frame[wire.WrapperLen:]; hex.EncodeToString(got) != hex.EncodeToString(gurux) {
		t.Fatalf("AARQ APDU:\n got  %x\n want %x (Gurux public client)", got, gurux)
	}

	// The InitiateRequest inside user-information (BE .. 04 len ..).
	captured := "01000000065f1f040000fe1dffff" // zeus8497 dlms.pcap, first AARQ
	ours := hex.EncodeToString(frame[len(frame)-14:])
	if len(ours) != len(captured) {
		t.Fatalf("InitiateRequest length %d, captured one %d", len(ours)/2, len(captured)/2)
	}
	// Same octets outside the 3 conformance bits (offsets 9..11).
	if ours[:18] != captured[:18] || ours[24:] != captured[24:] {
		t.Fatalf("InitiateRequest layout differs from the real capture:\n ours     %s\n captured %s", ours, captured)
	}
}
