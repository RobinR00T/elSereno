package wire_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/melsoft/wire"
)

// TestRealCapture validates the MELSOFT fingerprint against a real
// exchange, byte for byte from hi-KK/ICS-Protocol-identify
// "Mitsubishi Q系列PLC CPU型号识别.pcapng" (TCP/5007, a real MELSEC
// Q-series CPU answering GX Works direct-connection). The capture is
// cross-checked against the plcscan/DigitalBond melsecq-discover.nse
// shipped alongside it: the NSE sends exactly this getcpuinfopack and
// validates a first response byte of 0xd7, reading the CPU model at
// 1-based offset 42.
func TestRealCapture(t *testing.T) {
	// Client request, verbatim from the capture (and the NSE getcpuinfopack).
	req, err := hex.DecodeString("57000000001111070000ffff030000fe03000014001c080a0800000000000000040101010000000001")
	if err != nil {
		t.Fatal(err)
	}
	if got := wire.BuildGetCPUInfo(); !bytes.Equal(got, req) {
		t.Fatalf("BuildGetCPUInfo = %x, want the real capture request %x", got, req)
	}

	// Server response, verbatim from the capture: 0xd7 marker, CPU model
	// "Q03UDECPU" at the reference offset.
	resp, err := hex.DecodeString("d700c80000111107000000e40300ffff03000038009c000c08000000001004000000000101010000005130335544454350552020202020202068020008baba081020210316002002000101e802")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the real model string is present in the bytes.
	if !strings.Contains(string(resp), "Q03UDECPU") {
		t.Fatal("test vector lost the Q03UDECPU model string")
	}
	if !wire.IsResponseFrame(resp) {
		t.Fatal("IsResponseFrame = false on a real MELSOFT response")
	}
	info, err := wire.ParseCPUInfo(resp)
	if err != nil {
		t.Fatalf("ParseCPUInfo rejected a real MELSOFT response: %v", err)
	}
	if info.Model != "Q03UDECPU" {
		t.Fatalf("model: got %q want %q", info.Model, "Q03UDECPU")
	}
}
