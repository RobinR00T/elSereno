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
