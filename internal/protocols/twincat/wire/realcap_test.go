package wire

import (
	"encoding/hex"
	"testing"
)

// realReadDeviceInfoResp is a real TwinCAT ADS "Read Device Info" response
// (AMS/TCP frame, command 0x0001, state flags 0x0005 = ADS response) taken
// verbatim from w3h/icsmaster pcap/beckoff/beckoffiplinktc3.pcapng, a real
// TwinCAT 2 runtime answering on TCP/48898. The 24-byte payload is
// error(4)=0 + major(1)=2 + minor(1)=11 + build(2)=2103 + name(16)=
// "PLC Server", which confirms on real bytes that the device-name field is
// 16 bytes (payload 24), not 24 (payload 32).
const realReadDeviceInfoResp = "000038000000c0a8016301011180050d7560010120030100" +
	"050018000000000000008f00000000000000020b3708" +
	"504c4320536572766572000000000000"

// TestParseDeviceInfo_RealResponse validates the ADS ReadDeviceInfo parser
// against a real capture byte for byte: the AMS/TCP framing, the AMS routing
// header (command id + response state flag + data length), and the response
// payload (error code, version triple, 16-byte device name). This upgrades
// TwinCAT from spec cross-check to real-capture validated.
func TestParseDeviceInfo_RealResponse(t *testing.T) {
	buf, err := hex.DecodeString(realReadDeviceInfoResp)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != 62 {
		t.Fatalf("frame length = %d, want 62 (38-byte headers + 24-byte payload)", len(buf))
	}

	info, perr := ParseDeviceInfo(buf)
	if perr != nil {
		t.Fatalf("ParseDeviceInfo rejected a real ReadDeviceInfo response: %v", perr)
	}
	if info.MajorVersion != 2 {
		t.Errorf("MajorVersion = %d, want 2", info.MajorVersion)
	}
	if info.MinorVersion != 11 {
		t.Errorf("MinorVersion = %d, want 11", info.MinorVersion)
	}
	if info.VersionBuild != 2103 {
		t.Errorf("VersionBuild = %d, want 2103", info.VersionBuild)
	}
	if info.Name != "PLC Server" {
		t.Errorf("Name = %q, want %q", info.Name, "PLC Server")
	}
}
