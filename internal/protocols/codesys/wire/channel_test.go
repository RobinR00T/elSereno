package wire_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/codesys/wire"
)

// TestBuildChannelOpen_TenableReference validates BuildChannelOpen byte
// for byte against the Tenable CODESYS gateway V3 PoC's channel-open
// frame, computed with a fixed client id (0x11223344). The expected
// vector was produced by a faithful port of the PoC's layer3 /
// layer4_meta / block-driver construction (scratchpad codesys_chanopen.py).
func TestBuildChannelOpen_TenableReference(t *testing.T) {
	const clientID = 0x11223344
	want, err := hex.DecodeString("000117e830000000c56b404000430000000000000000000000000000c30001014a8240974433221100401f0008000000")
	if err != nil {
		t.Fatal(err)
	}
	got := wire.BuildChannelOpen(clientID)
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildChannelOpen(0x%08x):\n got  %x\n want %x", clientID, got, want)
	}
}

// TestBuildChannelOpen_Structure checks the stable framing invariants
// that hold for any client id: the Block Driver magic prefix, the
// little-endian total-length field (which includes the 8-byte header and
// equals the frame length), and that the client id lands in the datagram
// payload.
func TestBuildChannelOpen_Structure(t *testing.T) {
	const clientID = 0xDEADBEEF
	f := wire.BuildChannelOpen(clientID)
	if !bytes.HasPrefix(f, wire.BlockDriverMagic) {
		t.Fatalf("frame does not start with the Block Driver magic: %x", f[:4])
	}
	// bytes 4..7 are the LE total length including the 8-byte header.
	gotLen := uint32(f[4]) | uint32(f[5])<<8 | uint32(f[6])<<16 | uint32(f[7])<<24
	if int(gotLen) != len(f) {
		t.Fatalf("length field %d != frame length %d", gotLen, len(f))
	}
	// The client id (LE) must be present in the datagram payload.
	idLE := []byte{0xEF, 0xBE, 0xAD, 0xDE}
	if !bytes.Contains(f, idLE) {
		t.Fatalf("client id not found in frame: %x", f)
	}
	// A real gateway reply is recognised by the existing Block Driver
	// magic path; a frame that echoes the magic classifies as CoDeSys.
	if note, err := wire.Classify(f); err != nil || note != "BlockDriver magic" {
		t.Fatalf("self-built frame should classify by magic: note=%q err=%v", note, err)
	}
}
