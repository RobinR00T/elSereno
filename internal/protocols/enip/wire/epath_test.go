package wire

import (
	"errors"
	"testing"
)

// TestParseMRPath_8bit pins the 2-byte logical-segment forms.
// 0x21 0xCC = class CC (8-bit class).
func TestParseMRPath_8bit(t *testing.T) {
	// EPATH: class=0x01 instance=0x01 attr=0x07
	path := []byte{
		0x20, 0x01, // class8 = 0x01
		0x24, 0x01, // instance8 = 0x01
		0x30, 0x07, // attr8 = 0x07
	}
	got, err := ParseMRPath(path)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !got.HasClass || got.Class != 1 {
		t.Errorf("class: %+v", got)
	}
	if !got.HasInstance || got.Instance != 1 {
		t.Errorf("instance: %+v", got)
	}
	if !got.HasAttr || got.Attribute != 7 {
		t.Errorf("attr: %+v", got)
	}
}

// TestParseMRPath_16bit pins the 4-byte logical-segment
// forms (8-bit type byte + pad + 2-byte LE value).
func TestParseMRPath_16bit(t *testing.T) {
	path := []byte{
		0x21, 0x00, 0x42, 0x01, // class16 = 0x0142 (322)
		0x25, 0x00, 0x05, 0x00, // instance16 = 5
	}
	got, err := ParseMRPath(path)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.Class != 0x0142 {
		t.Errorf("class = 0x%x, want 0x0142", got.Class)
	}
	if got.Instance != 5 {
		t.Errorf("instance = %d, want 5", got.Instance)
	}
	if got.HasAttr {
		t.Errorf("HasAttr should be false")
	}
}

// TestParseMRPath_UnknownSegment rejects port-segments
// (0x00..0x1F top bits) and any other non-logical
// segment type.
func TestParseMRPath_UnknownSegment(t *testing.T) {
	path := []byte{0x00, 0x01, 0x02} // port segment, unknown
	_, err := ParseMRPath(path)
	if !errors.Is(err, ErrEPathUnknownSegment) {
		t.Errorf("err = %v, want ErrEPathUnknownSegment", err)
	}
}

// TestParseMRPath_TruncatedSegment refuses paths that
// claim more bytes than available.
func TestParseMRPath_TruncatedSegment(t *testing.T) {
	path := []byte{0x21, 0x00, 0x42} // class16 needs 4 bytes
	_, err := ParseMRPath(path)
	if !errors.Is(err, ErrEPathTooShort) {
		t.Errorf("err = %v, want ErrEPathTooShort", err)
	}
}

// TestExtractMRTarget builds a SendRRData body with one
// Unconnected Data Item containing a service+path and
// asserts the target is recovered.
func TestExtractMRTarget(t *testing.T) {
	mr := []byte{
		0x10, 0x03, // service=0x10 (Set Attribute Single), pathSize=3 words
		0x20, 0x01, // class8 = 0x01
		0x24, 0x01, // instance8 = 0x01
		0x30, 0x07, // attr8 = 0x07
	}
	body := []byte{
		0x00, 0x00, 0x00, 0x00, // InterfaceHandle = 0
		0x00, 0x00, // Timeout
		0x02, 0x00, // ItemCount = 2
		// Item 1: Null Address (TypeID 0x0000, Length 0)
		0x00, 0x00, 0x00, 0x00,
		// Item 2: Unconnected Data (TypeID 0x00B2, Length len(mr))
		0xB2, 0x00, byte(len(mr)), 0x00, // #nosec G115 -- test fixture, len bounded
	}
	body = append(body, mr...)

	got, ok := ExtractMRTarget(body)
	if !ok {
		t.Fatalf("ExtractMRTarget = false")
	}
	if got.Class != 1 || got.Instance != 1 || got.Attribute != 7 {
		t.Errorf("got %+v, want {Class:1 Instance:1 Attribute:7}", got)
	}
}

// TestExtractMRTarget_MalformedBody returns false on a
// truncated CPF header.
func TestExtractMRTarget_MalformedBody(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // InterfaceHandle + Timeout, no CPF
	if _, ok := ExtractMRTarget(body); ok {
		t.Errorf("expected false on truncated body")
	}
}
