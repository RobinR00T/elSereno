package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/enip/wire"
)

// TestParseListIdentity_RealCapture validates ParseListIdentity against a
// real ListIdentity reply (ENIP command 0x63), byte for byte from CISA
// cisagov/icsnpp-enip testing/traces/enip_cip_example.pcap: an Allen-Bradley
// 1756-ENBT/A EtherNet/IP module. The body is the ENIP command data (the
// bytes after the 24-byte encapsulation header), which is what the enip probe
// passes to ParseListIdentity.
//
// This closes the long-standing capture gap: earlier in the project the only
// reachable ENIP captures carried CIP session messaging (0x6f/0x70) with no
// ListIdentity reply, so ParseListIdentity was spec-grounded only.
func TestParseListIdentity_RealCapture(t *testing.T) {
	body, err := hex.DecodeString(
		"01000c002d0001000002af120a0101a4000000000000000001000c003a00040330008e4d52000b313735362d454e42542f4103")
	if err != nil {
		t.Fatal(err)
	}
	it, err := wire.ParseListIdentity(body)
	if err != nil {
		t.Fatalf("ParseListIdentity on a real reply: %v", err)
	}
	if it.VendorID != 1 { // Rockwell Automation / Allen-Bradley
		t.Errorf("VendorID=%d, want 1", it.VendorID)
	}
	if it.DeviceType != 12 {
		t.Errorf("DeviceType=%d, want 12", it.DeviceType)
	}
	if it.ProductCode != 58 {
		t.Errorf("ProductCode=%d, want 58", it.ProductCode)
	}
	if it.Revision != 0x0403 { // major 4, minor 3
		t.Errorf("Revision=0x%04x, want 0x0403", it.Revision)
	}
	if it.Status != 0x0030 {
		t.Errorf("Status=0x%04x, want 0x0030", it.Status)
	}
	if it.SerialNumber != 0x00524d8e {
		t.Errorf("SerialNumber=0x%08x, want 0x00524d8e", it.SerialNumber)
	}
	if it.ProductName != "1756-ENBT/A" {
		t.Errorf("ProductName=%q, want 1756-ENBT/A", it.ProductName)
	}
}
