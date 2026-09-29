package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// hexb decodes a hex string fixture or fails the test.
func hexb(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// Real captured bytes from ITI/ICS-Security-Tools
// s7comm_reading_plc_status.pcap, taken after the 4-byte TPKT header
// (COTP DT + S7 PDU), so they match what the builders return and what
// the parsers take (via S7PDU). The capture's client pduRefs are 0x0200
// (Setup) and 0x0300 (the first SZL 0x0132/0x0004 read).
const (
	realSetupReq  = "02f08032010000020000080000f0000001000101e0"
	realSetupResp = "02f080320300000200000800000000f0000001000100f0"
)

func TestBuildSetupCommunication_RealBytes(t *testing.T) {
	got := BuildSetupCommunication(0x0200)
	want := hexb(t, realSetupReq)
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildSetupCommunication mismatch\n got % x\nwant % x", got, want)
	}
}

func TestS7PDU_And_ParseSetupResponse_RealBytes(t *testing.T) {
	payload := hexb(t, realSetupResp)
	pdu, ok := S7PDU(payload)
	if !ok {
		t.Fatal("S7PDU: could not extract S7 PDU from real Setup response")
	}
	if pdu[0] != 0x32 || pdu[1] != ROSCTRAckData {
		t.Fatalf("extracted PDU is not an AckData: % x", pdu[:2])
	}
	n, ok := ParseSetupResponse(pdu)
	if !ok {
		t.Fatal("ParseSetupResponse ok=false on real bytes")
	}
	if n != 240 { // negotiated PDU length 0x00F0
		t.Fatalf("negotiated PDU length = %d, want 240", n)
	}
}

func TestS7PDU_RejectsNonData(t *testing.T) {
	// A COTP Connection Confirm payload (not a Data PDU) must be rejected.
	cc := []byte{0x11, COTPConnectionConfirm, 0x00, 0x0f, 0x00, 0x03}
	if _, ok := S7PDU(cc); ok {
		t.Fatal("S7PDU accepted a non-Data COTP payload")
	}
}
