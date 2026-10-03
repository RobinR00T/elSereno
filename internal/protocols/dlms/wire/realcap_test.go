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
