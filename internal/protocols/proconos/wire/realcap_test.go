package wire_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/proconos/wire"
)

// TestRealCapture validates the ProConOS fingerprint against a real exchange,
// byte for byte from hi-KK/ICS-Protocol-identify "ProConOs协议识别.pcapng"
// (TCP/20547, a real ProConOS V4.2.0214 runtime on a "QuickMix" controller).
// The capture is cross-checked against the DigitalBond Redpoint
// proconos-info.nse shipped alongside it: the NSE sends exactly
// cc01000b4002000047ee and validates a first response byte of 0xcc, which is
// what BuildHello sends and what Classify keys on.
func TestRealCapture(t *testing.T) {
	// Client request, verbatim from the capture (packet 1) and identical to
	// the Redpoint proconos-info.nse req_info.
	req, err := hex.DecodeString("cc01000b4002000047ee")
	if err != nil {
		t.Fatal(err)
	}
	if got := wire.BuildHello(); !bytes.Equal(got, req) {
		t.Fatalf("BuildHello = %x, want the real capture request %x", got, req)
	}

	// Server response, verbatim from the capture (packet 2): 0xcc signature,
	// then the ProConOS runtime / firmware / project banner fields.
	resp, err := hex.DecodeString("cc003030303030303030300050726f436f6e4f532056342e322e30323134204f6374203238203230313100205620332e3935412e36202020202020204d6172202039203230313200202020202020517569636b4d697800517569636b4d6978006e2f6100")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the real runtime banner is present in the bytes.
	if !strings.Contains(string(resp), "ProConOS V4.2.0214") {
		t.Fatal("test vector lost the ProConOS runtime banner")
	}

	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify rejected a real ProConOS response: %v", err)
	}
	if !strings.Contains(note, "0xcc") {
		t.Errorf("Classify note = %q, want the 0xcc signature match", note)
	}
	if !wire.IsProConOSFrame(resp) {
		t.Error("IsProConOSFrame = false on a real ProConOS response")
	}

	// The banner-substring fallback must also catch this response on its own
	// (drop the leading 0xcc so the signature path cannot fire).
	noSig := append([]byte{0x00}, resp[1:]...)
	if note, err := wire.Classify(noSig); err != nil || !strings.Contains(note, "banner=") {
		t.Errorf("banner fallback failed on real response: note=%q err=%v", note, err)
	}
}
