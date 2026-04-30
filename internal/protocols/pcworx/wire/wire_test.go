package wire_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/pcworx/wire"
)

func TestBuildHello_LengthAndPrefix(t *testing.T) {
	frame := wire.BuildHello()
	if len(frame) != wire.HelloLen {
		t.Fatalf("hello len = %d, want %d", len(frame), wire.HelloLen)
	}
	if !bytes.HasPrefix(frame, wire.PCWorxHelloPrefix) {
		t.Errorf("hello does not start with PCWorx prefix: % x", frame[:4])
	}
	if !bytes.Equal(frame[4:12], wire.PCWorxIdentifyToken) {
		t.Errorf("identify token mismatch: % x", frame[4:12])
	}
	for i := 12; i < len(frame); i++ {
		if frame[i] != 0 {
			t.Errorf("byte[%d] = %02x, want 0", i, frame[i])
		}
	}
}

func TestClassify_PrefixEcho(t *testing.T) {
	resp := append([]byte{}, wire.PCWorxHelloPrefix...)
	resp = append(resp, []byte{0x00, 0x01, 0x02, 0x03}...) // any payload
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(note, "prefix echo") {
		t.Errorf("note = %q, want prefix-echo signal", note)
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
	// Some ILC firmwares report ProConOS as the runtime name —
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
	if !wire.IsPCWorxFrame(append(wire.PCWorxHelloPrefix, 0xFF)) {
		t.Error("IsPCWorxFrame: prefix-matching frame returned false")
	}
	if wire.IsPCWorxFrame([]byte{0xff, 0xff, 0xff, 0xff}) {
		t.Error("IsPCWorxFrame: non-matching frame returned true")
	}
	if wire.IsPCWorxFrame([]byte{0x01}) {
		t.Error("IsPCWorxFrame: short frame returned true")
	}
}
