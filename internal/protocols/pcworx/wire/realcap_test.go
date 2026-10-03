package wire_test

import (
	"encoding/hex"
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
