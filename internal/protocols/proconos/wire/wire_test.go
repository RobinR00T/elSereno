package wire_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/proconos/wire"
)

func TestBuildHello_LengthAndPrefix(t *testing.T) {
	frame := wire.BuildHello()
	if len(frame) != wire.HelloLen {
		t.Fatalf("hello len = %d, want %d", len(frame), wire.HelloLen)
	}
	if !bytes.HasPrefix(frame, wire.ProConOSHelloPrefix) {
		t.Errorf("hello does not start with ProConOS prefix: % x", frame[:4])
	}
	if !bytes.Equal(frame[4:12], wire.ProConOSToken) {
		t.Errorf("identify token mismatch: got %q want %q", string(frame[4:12]), string(wire.ProConOSToken))
	}
	for i := 12; i < len(frame); i++ {
		if frame[i] != 0 {
			t.Errorf("byte[%d] = %02x, want 0", i, frame[i])
		}
	}
}

func TestClassify_PrefixEcho(t *testing.T) {
	resp := append([]byte{}, wire.ProConOSHelloPrefix...)
	resp = append(resp, []byte{0x00, 0x01, 0x02, 0x03}...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(strings.ToLower(note), "prefix echo") {
		t.Errorf("note = %q, want prefix-echo signal", note)
	}
}

func TestClassify_BannerProConOS(t *testing.T) {
	resp := []byte{0xff, 0xfe, 0xab, 0xcd, 'P', 'R', 'O', 'C', 'O', 'N', 'O', 'S', ' ', 'V', '5', '.', '0'}
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(strings.ToUpper(note), "PROCONOS") {
		t.Errorf("note = %q, want PROCONOS marker", note)
	}
}

func TestClassify_BannerKWSoftware(t *testing.T) {
	resp := append([]byte{0x00, 0x01, 0x02, 0x03}, []byte("KW-Software MultiProg V5.61")...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if note == "" {
		t.Errorf("expected positive note for KW-Software banner")
	}
}

func TestClassify_BannerMultiProg(t *testing.T) {
	resp := append([]byte{0xde, 0xad, 0xbe, 0xef}, []byte("MultiProg-wt 5.61.4")...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(note, "MultiProg") {
		t.Errorf("note = %q, want MultiProg marker", note)
	}
}

func TestClassify_AlternatePrefixCafeDeCade(t *testing.T) {
	// The "01 06 00 10 + PROCONOS" form is the v1.28 canonical
	// hello, but some Berghof + Lenze firmwares respond with the
	// older "0xCA 0xFE 0x00 0x00 0xCE 0xFA 0xDE 0xC0" structure.
	// The classifier accepts both as positive ID via the alt-
	// prefix banner substring.
	resp := []byte{0xCA, 0xFE, 0x00, 0x00, 0xCE, 0xFA, 0xDE, 0xC0, 0x01, 0x02, 0x03, 0x04}
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify alt-prefix: %v", err)
	}
	if note == "" {
		t.Errorf("expected positive note for alt-prefix response")
	}
}

func TestClassify_ShortFrame(t *testing.T) {
	_, err := wire.Classify([]byte{0x01, 0x06})
	if !errors.Is(err, wire.ErrShortFrame) {
		t.Fatalf("err = %v, want ErrShortFrame", err)
	}
}

func TestClassify_NotProConOS(t *testing.T) {
	resp := []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	_, err := wire.Classify(resp)
	if !errors.Is(err, wire.ErrNotProConOS) {
		t.Fatalf("err = %v, want ErrNotProConOS", err)
	}
}

func TestIsProConOSFrame(t *testing.T) {
	if !wire.IsProConOSFrame(append(wire.ProConOSHelloPrefix, 0xFF)) {
		t.Error("prefix-matching frame returned false")
	}
	if wire.IsProConOSFrame([]byte{0xff, 0xff, 0xff, 0xff}) {
		t.Error("non-matching frame returned true")
	}
	if wire.IsProConOSFrame([]byte{0x01}) {
		t.Error("short frame returned true")
	}
}
