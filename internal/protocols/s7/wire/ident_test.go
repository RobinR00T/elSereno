package wire

import (
	"bytes"
	"testing"
)

// Real captured bytes (ITI/ICS-Security-Tools s7comm_reading_plc_status.pcap),
// after the 4-byte TPKT header. The reads used pduRef 0x1100 (SZL 0x0011)
// and 0x1400 (SZL 0x001C). The CPU is an IM151-8 PN/DP CPU, order number
// 6ES7 151-8AB01-0AB0, firmware V3.2.6, serial "S C-C6TW74882012".
const (
	realModuleIdentReq  = "02f080320700001100000800080001120411440100ff09000400110000"
	realCompIdentReq    = "02f080320700001400000800080001120411440100ff090004001c0000"
	realModuleIdentResp = "02f080320700001100000c007c000112081284010200000000ff09007800110000001c0004000136455337203135312d38414230312d304142302000c000030001000636455337203135312d38414230312d304142302000c0000300010007202020202020202020202020202020202020202000c0560302060081426f6f74204c6f61646572202020202020202020000041200909"
	realCompIdentResp   = "02f080320700001400000c00da000112081284010206010000ff0900d6001c00000022000a0001494d3135312d382d4350550000000000000000000000000000000000000000000002494d3135312d3820504e2f4450204350550000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000044f726967696e616c205369656d656e732045717569706d656e7400000000000000055320432d433654573734383832303132000000000000000000000000000000000007494d3135312d3820504e2f4450204350550000000000000000000000000000000008"
)

func recByIndex(recs []ModuleIdentRecord, idx uint16) (ModuleIdentRecord, bool) {
	for _, r := range recs {
		if r.Index == idx {
			return r, true
		}
	}
	return ModuleIdentRecord{}, false
}

func compByIndex(recs []IdentRecord, idx uint16) (IdentRecord, bool) {
	for _, r := range recs {
		if r.Index == idx {
			return r, true
		}
	}
	return IdentRecord{}, false
}

func TestBuildReadSZLRequest_Ident_RealBytes(t *testing.T) {
	if got, want := BuildReadSZLRequest(0x1100, SZLIDModuleIdent, 0), hexb(t, realModuleIdentReq); !bytes.Equal(got, want) {
		t.Errorf("module-ident request\n got % x\nwant % x", got, want)
	}
	if got, want := BuildReadSZLRequest(0x1400, SZLIDComponentIdent, 0), hexb(t, realCompIdentReq); !bytes.Equal(got, want) {
		t.Errorf("component-ident request\n got % x\nwant % x", got, want)
	}
}

func TestParseModuleIdent_RealBytes(t *testing.T) {
	pdu, ok := S7PDU(hexb(t, realModuleIdentResp))
	if !ok {
		t.Fatal("S7PDU")
	}
	recs, ok := ParseModuleIdent(pdu)
	if !ok {
		t.Fatal("ParseModuleIdent ok=false")
	}
	order, ok := recByIndex(recs, ModuleIndexOrderNumber)
	if !ok || order.MLFB != "6ES7 151-8AB01-0AB0" {
		t.Errorf("order number = %q (found=%v), want \"6ES7 151-8AB01-0AB0\"", order.MLFB, ok)
	}
	fw, ok := recByIndex(recs, ModuleIndexFirmware)
	if !ok || fw.Version != "V3.2.6" {
		t.Errorf("firmware version = %q (found=%v), want \"V3.2.6\"", fw.Version, ok)
	}
}

func TestParseComponentIdent_RealBytes(t *testing.T) {
	pdu, ok := S7PDU(hexb(t, realCompIdentResp))
	if !ok {
		t.Fatal("S7PDU")
	}
	recs, ok := ParseComponentIdent(pdu)
	if !ok {
		t.Fatal("ParseComponentIdent ok=false")
	}
	cases := map[uint16]string{
		ComponentIndexModuleName: "IM151-8 PN/DP CPU",
		ComponentIndexSerial:     "S C-C6TW74882012",
		ComponentIndexModuleType: "IM151-8 PN/DP CPU",
	}
	for idx, want := range cases {
		r, ok := compByIndex(recs, idx)
		if !ok || r.Text != want {
			t.Errorf("component idx %d = %q (found=%v), want %q", idx, r.Text, ok, want)
		}
	}
}

func TestParseModuleIdent_WrongSZL(t *testing.T) {
	// A protection response (0x0132) must not parse as module ident (0x0011).
	pdu, ok := S7PDU(hexb(t, realSZLResp))
	if !ok {
		t.Fatal("S7PDU")
	}
	if _, ok := ParseModuleIdent(pdu); ok {
		t.Fatal("ParseModuleIdent accepted a 0x0132 response")
	}
}
