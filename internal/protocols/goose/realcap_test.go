package goose_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/goose"
)

// realGOOSEFrame is packet 1 of w3h/icsmaster pcap/IEC61850/GOOSE/GOOSE.pcap,
// the complete Ethernet frame (dst MAC, src MAC, EtherType 0x88B8, then the
// GOOSE PDU) taken verbatim. It is a real IEC 61850-8-1 GOOSE heartbeat from
// a GE F650 relay (gocbRef "GEDeviceF650/LLN0$GO$gcb01"), not a hand-built
// fixture, so it exercises the BER-TLV APDU parser on bytes a real IED put on
// the wire.
const realGOOSEFrame = "01a0f4082f7700a0f4082f7788b80001009100000000618186" +
	"801a4745446576696365463635302f4c4c4e3024474f2467636230318103009c40" +
	"82184745446576696365463635302f4c4c4e3024474f4f534531830b463635305f" +
	"474f4f5345318408386ebbf34217280a85010186010a870100880101890100" +
	"8a0108ab208301008403030000830100840303000083010084030300008301008403030000"

// TestDissect_RealGOOSE validates the GOOSE dissector against a real capture
// byte for byte: EtherType demux, the reserved APPID/Length header, and the
// IECGoosePdu BER-TLV fields (gocbRef / timeAllowedToLive / datSet / goID /
// stNum / sqNum / confRev / numDatSetEntries). This is the "real capture" leg
// of the parser-validation matrix for GOOSE, which previously had only
// hand-built fixtures.
func TestDissect_RealGOOSE(t *testing.T) {
	frame, err := hex.DecodeString(realGOOSEFrame)
	if err != nil {
		t.Fatal(err)
	}

	f, err := goose.Dissect(frame)
	if err != nil {
		t.Fatalf("Dissect rejected a real GOOSE frame: %v", err)
	}
	if f.Kind != goose.KindGOOSE {
		t.Fatalf("Kind = %q, want %q", f.Kind, goose.KindGOOSE)
	}
	if f.VLAN {
		t.Error("VLAN = true, but this frame is not 802.1Q-tagged")
	}
	p := f.Goose
	if p == nil {
		t.Fatal("Goose PDU is nil")
	}

	if p.APPID != 0x0001 {
		t.Errorf("APPID = 0x%04x, want 0x0001", p.APPID)
	}
	if p.GocbRef != "GEDeviceF650/LLN0$GO$gcb01" {
		t.Errorf("GocbRef = %q", p.GocbRef)
	}
	if p.TimeAllowedToLive != 40000 {
		t.Errorf("TimeAllowedToLive = %d, want 40000", p.TimeAllowedToLive)
	}
	if p.DatSet != "GEDeviceF650/LLN0$GOOSE1" {
		t.Errorf("DatSet = %q", p.DatSet)
	}
	if p.GoID != "F650_GOOSE1" {
		t.Errorf("GoID = %q", p.GoID)
	}
	if p.StNum != 1 {
		t.Errorf("StNum = %d, want 1", p.StNum)
	}
	if p.SqNum != 10 {
		t.Errorf("SqNum = %d, want 10", p.SqNum)
	}
	if p.ConfRev != 1 {
		t.Errorf("ConfRev = %d, want 1", p.ConfRev)
	}
	if p.NumDatSetEntries != 8 {
		t.Errorf("NumDatSetEntries = %d, want 8", p.NumDatSetEntries)
	}
}

// realSVFrame is packet 1 of mgadelha/Sampled_Values SV_Normal_Traffic.cap,
// the complete Ethernet frame of a real IEC 61850-9-2 Sampled Values publish
// (dst MAC 01:0c:cd:04:00:02, the SV multicast range; 802.1Q-tagged;
// EtherType 0x88BA). It carries one ASDU (svID "4001", smpCnt 280, confRev 1,
// smpSynch 2) with 8 current/voltage samples, taken verbatim from a real
// merging-unit-style publisher.
const realSVFrame = "010ccd040002cafec0ffee698100800188ba40010066000000" +
	"00605c800101a2573055800434303031820201188304000000018501028740" +
	"fffe59820000000000043ddc00000000fffd6f5c00000000000006ba000020" +
	"00ff8df40000000000011dfbc200000000ff55600c0000000000014fce00002000"

// TestDissect_RealSV validates the Sampled Values path of the dissector
// against a real capture byte for byte: the 802.1Q + 0x88BA demux and the
// savPdu BER-TLV nesting (savPdu -> seqOfASDU -> ASDU: svID / smpCnt /
// confRev / smpSynch). This is the "real capture" leg for the SV parser,
// which previously had only hand-built fixtures.
func TestDissect_RealSV(t *testing.T) {
	frame, err := hex.DecodeString(realSVFrame)
	if err != nil {
		t.Fatal(err)
	}

	f, err := goose.Dissect(frame)
	if err != nil {
		t.Fatalf("Dissect rejected a real SV frame: %v", err)
	}
	if f.Kind != goose.KindSV {
		t.Fatalf("Kind = %q, want %q", f.Kind, goose.KindSV)
	}
	if !f.VLAN {
		t.Error("VLAN = false, but this SV frame is 802.1Q-tagged")
	}
	sv := f.SV
	if sv == nil {
		t.Fatal("SV PDU is nil")
	}
	if sv.APPID != 0x4001 {
		t.Errorf("APPID = 0x%04x, want 0x4001", sv.APPID)
	}
	if sv.NoASDU != 1 {
		t.Errorf("NoASDU = %d, want 1", sv.NoASDU)
	}
	if sv.SvID != "4001" {
		t.Errorf("SvID = %q, want %q", sv.SvID, "4001")
	}
	if sv.SmpCnt != 280 {
		t.Errorf("SmpCnt = %d, want 280", sv.SmpCnt)
	}
	if sv.ConfRev != 1 {
		t.Errorf("ConfRev = %d, want 1", sv.ConfRev)
	}
	if sv.SmpSynch != 2 {
		t.Errorf("SmpSynch = %d, want 2", sv.SmpSynch)
	}
}
