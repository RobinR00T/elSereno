package profinet_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/profinet"
)

// realIdentifyResponse is packet 2 of w3h/icsmaster pcap/profinet/
// ChangeIPUsingDCP.pcap: a real PROFINET DCP Identify response (FrameID
// 0xFEFF, ServiceID 0x05) from a station named "X208-BORD", taken verbatim
// as the full Ethernet frame (dst MAC, src MAC, EtherType 0x8892, then the
// DCP RT frame). Not a hand-built fixture: it is what a real PROFINET device
// answered to a DCP Identify-All on the wire, with the live block stream
// (DeviceOptions, TypeOfStation "INC", NameOfStation, DeviceID, DeviceRole,
// IP parameters).
const realIdentifyResponse = "000c29ba09ea08000693cf328892" + // Ethernet: dst, src, EtherType 0x8892
	"feff0501010000010000005e" + // DCP header: FrameID, ServiceID, ServiceType, XID, delay, DataLength=0x5e
	"0205001c0000010101020201020202030204020503" + // 02/05 DeviceOptions
	"3d0501050205030504ffff" + // (tail of the DeviceOptions value)
	"020100050000494e4300" + // 02/01 TypeOfStation "INC"
	"0202000b0000583230382d424f524400" + // 02/02 NameOfStation "X208-BORD"
	"020300060000002a0a01" + // 02/03 DeviceID: vendor 0x002a, device 0x0a01
	"0204000400000100" + // 02/04 DeviceRole 0x01
	"0102000e0001c0a80006ffffff00c0a80001" // 01/02 IP 192.168.0.6 / 255.255.255.0 / 192.168.0.1

// TestDecodeDCP_RealIdentifyResponse validates the PROFINET DCP decoder and
// the Identify-response flattener against a real capture byte for byte: the
// DCP RT header, the TLV block walk, and the device/IP fields an operator
// reads. This is the "real capture" leg of the parser-validation matrix for
// PROFINET, which previously had only hand-built fixtures.
func TestDecodeDCP_RealIdentifyResponse(t *testing.T) {
	full, err := hex.DecodeString(realIdentifyResponse)
	if err != nil {
		t.Fatal(err)
	}
	// DecodeDCP takes the bytes after the 14-byte Ethernet header (no VLAN).
	dcp := full[14:]

	f, err := profinet.DecodeDCP(dcp)
	if err != nil {
		t.Fatalf("DecodeDCP rejected a real DCP Identify response: %v", err)
	}
	if f.Header.FrameID != 0xFEFF {
		t.Errorf("FrameID = 0x%04x, want 0xFEFF", f.Header.FrameID)
	}
	if f.Header.ServiceID != 0x05 {
		t.Errorf("ServiceID = 0x%02x, want 0x05 (Identify)", f.Header.ServiceID)
	}

	r := profinet.ParseIdentifyResponse(f)
	if r.NameOfStation != "X208-BORD" {
		t.Errorf("NameOfStation = %q, want %q", r.NameOfStation, "X208-BORD")
	}
	if r.VendorID != 0x002a {
		t.Errorf("VendorID = 0x%04x, want 0x002a", r.VendorID)
	}
	if r.DeviceID != 0x0a01 {
		t.Errorf("DeviceID = 0x%04x, want 0x0a01", r.DeviceID)
	}
	if r.DeviceRole != 0x01 {
		t.Errorf("DeviceRole = 0x%02x, want 0x01", r.DeviceRole)
	}
	if got := r.IP.String(); got != "192.168.0.6" {
		t.Errorf("IP = %s, want 192.168.0.6", got)
	}
	if got := r.Subnet.String(); got != "255.255.255.0" {
		t.Errorf("Subnet = %s, want 255.255.255.0", got)
	}
	if got := r.Gateway.String(); got != "192.168.0.1" {
		t.Errorf("Gateway = %s, want 192.168.0.1", got)
	}
}
