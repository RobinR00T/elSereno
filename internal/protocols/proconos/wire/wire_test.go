package wire_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"local/elsereno/internal/protocols/proconos/wire"
)

func TestBuildHello_IsEnumerationRequest(t *testing.T) {
	frame := wire.BuildHello()
	if len(frame) != wire.RequestLen {
		t.Fatalf("request len = %d, want %d", len(frame), wire.RequestLen)
	}
	if !bytes.Equal(frame, wire.ProConOSRequest) {
		t.Errorf("request = % x, want % x", frame, wire.ProConOSRequest)
	}
	// Both the request and the reply lead with 0xcc.
	if frame[0] != wire.ResponseSignature {
		t.Errorf("request byte 0 = 0x%02x, want 0xcc", frame[0])
	}
}

func TestClassify_Signature(t *testing.T) {
	// A real ProConOS reply leads with the 0xcc response signature.
	resp := append([]byte{wire.ResponseSignature}, []byte{0x01, 0x00, 0x0b, 0x40}...)
	note, err := wire.Classify(resp)
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if !strings.Contains(strings.ToLower(note), "signature") {
		t.Errorf("note = %q, want signature signal", note)
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
	// Some Berghof + Lenze firmwares respond with the older
	// "0xCA 0xFE 0x00 0x00 0xCE 0xFA 0xDE 0xC0" structure; the
	// classifier accepts it via the alt-prefix banner substring.
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
	_, err := wire.Classify([]byte{})
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
	if !wire.IsProConOSFrame([]byte{0xcc, 0x01, 0x00, 0x0b}) {
		t.Error("0xcc-signature frame returned false")
	}
	if wire.IsProConOSFrame([]byte{0xff, 0xff, 0xff, 0xff}) {
		t.Error("non-matching frame returned true")
	}
	if wire.IsProConOSFrame([]byte{}) {
		t.Error("empty frame returned true")
	}
}
