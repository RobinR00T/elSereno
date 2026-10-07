package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/bacnet/wire"
)

// Real BACnet/IP bytes, byte for byte from CISA cisagov/icsnpp-bacnet
// testing/traces/bacnet_services.pcap. Validates the probe read path
// (BVLC header + I-Am detection) and one write-gate parser against real
// wire rather than hand-built fixtures.
func TestBACnet_RealCapture(t *testing.T) {
	// A real 22-byte Original-Unicast BVLC frame.
	bvlc, err := hex.DecodeString("810a001601240003016cff0203010c0c004000651955")
	if err != nil {
		t.Fatal(err)
	}
	h, err := wire.ParseBVLC(bvlc)
	if err != nil {
		t.Fatalf("ParseBVLC on a real frame: %v", err)
	}
	if h.Type != 0x81 || h.Function != 0x0a || h.Length != 22 {
		t.Errorf("BVLC = %+v, want type 0x81 func 0x0a len 22", h)
	}

	// A real I-Am APDU (unconfirmed-request, service 0x00), the response the
	// Who-Is probe keys on.
	iam, err := hex.DecodeString("1000c40200006c2201e09100212a")
	if err != nil {
		t.Fatal(err)
	}
	if !wire.IsIAm(iam) {
		t.Error("IsIAm returned false on a real I-Am response")
	}

	// A real WriteProperty confirmed-request (service 15). ParseWriteProperty
	// expects the service body, i.e. after the 4-byte confirmed-request
	// header. Target: object (type 1, instance 101), property 85 (Present_Value).
	wp, err := hex.DecodeString("0203020f0c0040006519553e44424800003f490a")
	if err != nil {
		t.Fatal(err)
	}
	tgt, ok := wire.ParseWriteProperty(wp[4:])
	if !ok {
		t.Fatal("ParseWriteProperty returned ok=false on a real request")
	}
	if tgt.ObjectType != 1 || tgt.ObjectInstance != 101 || tgt.PropertyID != 85 {
		t.Errorf("target = %+v, want type 1 instance 101 property 85", tgt)
	}
}

// TestBuildWhoIs_RealCapture validates the probe request: it is the
// Who-Is of CISA icsnpp-bacnet bacnet_example.pcap / bacnet_services.pcap
// byte for byte, except the BVLC function (0x0A original-unicast: the
// probe addresses one IP; the capture's is 0x0B original-broadcast).
// The hop count must be 255: the previous request had 0, which a
// BACnet router discards rather than forwarding.
func TestBuildWhoIs_RealCapture(t *testing.T) {
	captured, err := hex.DecodeString("810b000c0120ffff00ff1008")
	if err != nil {
		t.Fatal(err)
	}
	got := wire.BuildWhoIs()
	if len(got) != len(captured) {
		t.Fatalf("Who-Is length %d, captured %d", len(got), len(captured))
	}
	if got[1] != 0x0A {
		t.Errorf("BVLC function 0x%02x, want 0x0A (original-unicast)", got[1])
	}
	got[1] = captured[1]
	if hex.EncodeToString(got) != hex.EncodeToString(captured) {
		t.Fatalf("Who-Is (BVLC function aside):\n got  %x\n want %x", got, captured)
	}
}
