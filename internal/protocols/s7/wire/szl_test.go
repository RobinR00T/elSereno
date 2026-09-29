package wire

import (
	"bytes"
	"testing"
)

// Real captured bytes (ITI/ICS-Security-Tools s7comm_reading_plc_status.pcap),
// after the 4-byte TPKT header. The SZL 0x0132 index 4 read used pduRef
// 0x0300; the CPU answered with key=1, param=0, real=1, bart_sch=2 (RUN_P).
const (
	realSZLReq  = "02f080320700000300000800080001120411440100ff09000401320004"
	realSZLResp = "02f080320700000300000c0034000112081284010100000000ff090030" +
		"013200040028000100040001000000010002000000005656bc04a3d58401d6b2" +
		"02000000000000000000000000000000"
)

func TestBuildReadSZLRequest_RealBytes(t *testing.T) {
	got := BuildReadSZLRequest(0x0300, SZLIDProtection, SZLIndexProtection)
	want := hexb(t, realSZLReq)
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildReadSZLRequest mismatch\n got % x\nwant % x", got, want)
	}
}

func TestParseProtectionSZL_RealBytes(t *testing.T) {
	pdu, ok := S7PDU(hexb(t, realSZLResp))
	if !ok {
		t.Fatal("S7PDU: could not extract S7 PDU from real SZL response")
	}
	rec, ok := ParseProtectionSZL(pdu)
	if !ok {
		t.Fatal("ParseProtectionSZL ok=false on real bytes")
	}
	// From the capture: this CPU has effective protection level 1 with the
	// key switch in RUN_P, i.e. writes/control without a password.
	if rec.KeySwitchLevel != 1 {
		t.Errorf("KeySwitchLevel = %d, want 1", rec.KeySwitchLevel)
	}
	if rec.ParamLevel != 0 {
		t.Errorf("ParamLevel = %d, want 0", rec.ParamLevel)
	}
	if rec.RealLevel != 1 {
		t.Errorf("RealLevel = %d, want 1", rec.RealLevel)
	}
	if rec.ModeSelector != ModeSelectorRUNP {
		t.Errorf("ModeSelector = %d, want RUN_P (2)", rec.ModeSelector)
	}
}

// TestParseProtectionSZL_ProtectedNoData: a CPU that refuses the SZL read
// (or returns no data) yields ok=false, so the caller can treat it as a
// distinct "could not read protection" signal.
func TestParseProtectionSZL_ProtectedNoData(t *testing.T) {
	// UserData response header + response param + data area with return
	// code 0x0A (no data / not available), no SZL block.
	pdu := []byte{
		0x32, ROSCTRUserData, 0x00, 0x00, 0x03, 0x00, 0x00, 0x08, 0x00, 0x02,
		0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, // param (8)
		0x0A, 0x00, // data: return code 0x0A (object does not exist / no data)
	}
	if _, ok := ParseProtectionSZL(pdu); ok {
		t.Fatal("expected ok=false when the SZL read returns no data")
	}
}

// TestParseProtectionSZL_WrongSZL: a response for a different SZL-ID must
// not be misread as the protection record.
func TestParseProtectionSZL_WrongSZL(t *testing.T) {
	pdu, ok := S7PDU(hexb(t, realSZLResp))
	if !ok {
		t.Fatal("S7PDU")
	}
	// Flip the SZL-ID in the data area to 0x0131 and confirm rejection.
	// (find the 0x0132 in the SZL block header and mutate it.)
	i := bytes.Index(pdu, []byte{0x01, 0x32, 0x00, 0x04, 0x00, 0x28})
	if i < 0 {
		t.Fatal("could not locate SZL block header to mutate")
	}
	mutated := append([]byte(nil), pdu...)
	mutated[i+1] = 0x31 // 0x0132 -> 0x0131
	if _, ok := ParseProtectionSZL(mutated); ok {
		t.Fatal("expected ok=false for a non-0x0132 SZL response")
	}
}
