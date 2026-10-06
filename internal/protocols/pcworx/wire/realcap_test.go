package wire_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/pcworx/wire"
)

// TestClassify_RealCapture validates the PC Worx classifier against a real
// Phoenix Contact ILC exchange, byte for byte from reidmefirst/PC-PCAP
// proconos-connect-stop-then-start.pcap (TCP/1962, a Dragos training
// capture of an ILC 191 ETH 2TX PLC). The device-info response embeds the
// model string "ILC 191 ETH 2TX", which the classifier keys on.
func TestClassify_RealCapture(t *testing.T) {
	// Packet 4: PC Worx device-info response carrying the model + firmware.
	pkt, err := hex.DecodeString("810600b0000c00010000000000020000004c0000000000988295004a0000494c43203139312045544820325458000000000000000000000000000000000000000000342e343200000000000000000031312f32362f31350000000031383a34363a35350030340000000020000000000000000020000000000000000000000000000000200000000000000000200000000000000000303100323730303937360042300000002000000000200000000000")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the real model string is present in the bytes.
	if !strings.Contains(string(pkt), "ILC 191 ETH 2TX") {
		t.Fatal("test vector lost the ILC model string")
	}
	note, err := wire.Classify(pkt)
	if err != nil {
		t.Fatalf("Classify rejected a real PC Worx ILC response: %v", err)
	}
	if !strings.Contains(note, "ILC") {
		t.Errorf("Classify note = %q, want an ILC banner match", note)
	}
}

// TestInitExchange_RealCapture validates the session init against a second,
// independent real device: the ILC 151 ETH session in hi-KK/ICS-Protocol-
// identify "PCWorx协议识别.pcapng" (TCP/1962). The client's first packet is
// byte for byte our BuildHello (and the pcworx-info.nse init_comms), and
// every reply is an 0x81 frame whose big-endian length equals its size; the
// model string only arrives in the 0x06 device-info reply (PITF-072).
func TestInitExchange_RealCapture(t *testing.T) {
	req, err := hex.DecodeString("0101001a0000000078800003000c494245544830314e305f4d00")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.BuildHello(), req) {
		t.Fatalf("BuildHello differs from the captured init request")
	}
	replies := []struct {
		hex     string
		service byte
		banner  string
	}{
		{"81010014000000010000000000020000004c0000", 0x01, ""},
		{"81050012000100010000000000020000004c", 0x05, ""},
		{"810600b0000200010000000000020000004c0000000600988295004a0000494c43203135312045544800000000000000000000000000000000000000000000000000342e343100000000000000000030392f32382f31350000000031343a33353a30310030340000000020000000000000000020000000000000000000000000000000200000000000000000200000000000000000303100323730303937340042310000002000000000200000000000", 0x06, "ILC"},
	}
	for _, r := range replies {
		b, err := hex.DecodeString(r.hex)
		if err != nil {
			t.Fatal(err)
		}
		if !wire.IsPCWorxFrame(b) {
			t.Fatalf("service 0x%02x: real reply not recognised as a PC Worx frame", r.service)
		}
		if got := int(b[2])<<8 | int(b[3]); got != len(b) {
			t.Fatalf("service 0x%02x: length field %d != frame size %d", r.service, got, len(b))
		}
		note, err := wire.Classify(b)
		if err != nil {
			t.Fatalf("service 0x%02x: Classify: %v", r.service, err)
		}
		if !strings.Contains(note, fmt.Sprintf("service=0x%02x", r.service)) {
			t.Errorf("service 0x%02x: note = %q", r.service, note)
		}
		if r.banner != "" && !strings.Contains(note, r.banner) {
			t.Errorf("service 0x%02x: note = %q, want banner %q", r.service, note, r.banner)
		}
	}
}
