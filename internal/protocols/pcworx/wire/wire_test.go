package wire_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/pcworx/wire"
)

func TestBuildHello_IsNSEInit(t *testing.T) {
	// The session-init request, byte for byte the init_comms of nmap's
	// pcworx-info.nse and the client's first packet in the real ILC 151 ETH
	// capture (PITF-072).
	want, err := hex.DecodeString("0101001a0000000078800003000c494245544830314e305f4d00")
	if err != nil {
		t.Fatal(err)
	}
	frame := wire.BuildHello()
	if !bytes.Equal(frame, want) {
		t.Fatalf("hello = % x\nwant    % x", frame, want)
	}
	if len(frame) != wire.HelloLen {
		t.Fatalf("hello len = %d, want %d", len(frame), wire.HelloLen)
	}
	frame[0] = 0xFF // BuildHello must return a copy
	if wire.BuildHello()[0] != 0x01 {
		t.Fatal("BuildHello leaked its backing array")
	}
}

func TestClassify_ResponseFrame(t *testing.T) {
	// The real ILC 151 ETH reply to the session init: 0x81, service 0x01,
	// big-endian length 0x0014 = 20 = the frame size.
	resp, err := hex.DecodeString("81010014000000010000000000020000004c0000")
	if err != nil {
		t.Fatal(err)
	}
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if note != "response service=0x01" {
		t.Errorf("note = %q, want %q", note, "response service=0x01")
	}
}

// TestClassify_RequestShapedIsNotPCWorx: a buffer that starts like our own
// request (the current init or the old 01 01 00 1C hello) is not a PC Worx
// response. The old classifier accepted the latter as "prefix echo", which
// confirmed a reflected probe as PC Worx (PITF-071 / PITF-072).
func TestClassify_RequestShapedIsNotPCWorx(t *testing.T) {
	for _, resp := range [][]byte{
		wire.BuildHello(),
		{0x01, 0x01, 0x00, 0x1C, 0x00, 0x01, 0x02, 0x03},
	} {
		if _, err := wire.Classify(resp); !errors.Is(err, wire.ErrNotPCWorx) {
			t.Errorf("Classify(% x) err = %v, want ErrNotPCWorx", resp, err)
		}
	}
}

func TestClassify_BannerILC(t *testing.T) {
	resp := []byte{0xff, 0xfe, 0xab, 0xcd, 'I', 'L', 'C', ' ', '3', '5', '0', ' ', 'P', 'N', 0x00, 'F', 'W', ' ', 'V', '4', '.', '5'}
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(strings.ToLower(note), "ilc") {
		t.Errorf("note = %q, want ILC banner match", note)
	}
}

func TestClassify_BannerPhoenix(t *testing.T) {
	resp := append([]byte{0xde, 0xad, 0xbe, 0xef}, []byte("Phoenix Contact PCWorx")...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if note == "" {
		t.Errorf("note is empty for Phoenix banner; want a non-empty positive marker")
	}
}

func TestClassify_BannerProConOS(t *testing.T) {
	// Some ILC firmwares report ProConOS as the runtime name,
	// PCWorx and ProConOS share a kernel from KW-Software in
	// many ILC releases. Confirm the banner list catches both.
	resp := append([]byte{0x11, 0x22, 0x33, 0x44}, []byte("ProConOS V5.0.0.40")...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(note, "ProConOS") {
		t.Errorf("note = %q, want ProConOS marker", note)
	}
}

func TestClassify_ShortFrame(t *testing.T) {
	_, err := wire.Classify([]byte{0x01, 0x01})
	if !errors.Is(err, wire.ErrShortFrame) {
		t.Fatalf("err = %v, want ErrShortFrame", err)
	}
}

func TestClassify_NotPCWorx(t *testing.T) {
	// HTTP-shaped junk: 4-byte prefix doesn't match, no PCWorx
	// banner substrings.
	resp := []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	_, err := wire.Classify(resp)
	if !errors.Is(err, wire.ErrNotPCWorx) {
		t.Fatalf("err = %v, want ErrNotPCWorx", err)
	}
}

func TestIsPCWorxFrame(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want bool
	}{
		{"real init reply (81 01, len 20)", []byte{0x81, 0x01, 0x00, 0x14, 0x00}, true},
		{"real device-info reply (81 06, len 176)", []byte{0x81, 0x06, 0x00, 0xb0}, true},
		{"length below the 4-byte header", []byte{0x81, 0x01, 0x00, 0x03}, false},
		{"implausible length", []byte{0x81, 0x01, 0xff, 0xff}, false},
		{"our own request", wire.BuildHello(), false},
		{"short", []byte{0x81}, false},
	}
	for _, c := range cases {
		if got := wire.IsPCWorxFrame(c.buf); got != c.want {
			t.Errorf("%s: IsPCWorxFrame = %v, want %v", c.name, got, c.want)
		}
	}
}
