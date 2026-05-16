package wire

import (
	"bytes"
	"strings"
	"testing"
)

// TestExtractMMSVendorHint_Siemens: a synthetic AARE blob with
// "SIEMENS SIPROTEC" embedded surfaces the longer marker first
// (curated-list ordering invariant).
func TestExtractMMSVendorHint_Siemens(t *testing.T) {
	// Synthetic blob: random BER-ish junk + the vendor string +
	// firmware-style trailing data.
	buf := []byte{
		0xA1, 0x80, 0x02, 0x01, 0x01,
		0x1A, 0x14, 'S', 'I', 'E', 'M', 'E', 'N', 'S', ' ',
		'S', 'I', 'P', 'R', 'O', 'T', 'E', 'C', ' ', '5', '5', '4',
		0x00, 0x00, 0x00, // non-printable trailing
	}
	hint := ExtractMMSVendorHint(buf)
	if hint == "" {
		t.Fatal("expected non-empty vendor hint")
	}
	if !strings.Contains(hint, "SIEMENS SIPROTEC") {
		t.Errorf("hint = %q, want SIEMENS SIPROTEC", hint)
	}
}

// TestExtractMMSVendorHint_None: no marker present → empty.
func TestExtractMMSVendorHint_None(t *testing.T) {
	buf := []byte{0xA1, 0x80, 0x02, 0x01, 0x01, 0x1A, 0x05, 'X', 'Y', 'Z', 'A', 'B'}
	if ExtractMMSVendorHint(buf) != "" {
		t.Errorf("expected empty hint, got %q", ExtractMMSVendorHint(buf))
	}
}

// TestExtractMMSVendorHint_Sanitises: non-printable bytes
// around the marker get replaced with dots.
func TestExtractMMSVendorHint_Sanitises(t *testing.T) {
	buf := []byte{
		0x01, 0x02, 0x03, // non-printable pre
		'A', 'B', 'B', ' ', 'R', 'E', 'L', 'I', 'O', 'N', // marker
		0xFF, 0xFE, // non-printable trailing
	}
	hint := ExtractMMSVendorHint(buf)
	if !strings.Contains(hint, "ABB RELION") {
		t.Errorf("hint missing marker: %q", hint)
	}
	if !strings.Contains(hint, "...") && !strings.Contains(hint, ".") {
		t.Errorf("expected dots for non-printable bytes; got %q", hint)
	}
}

// TestBuildMMSGetServerDirectoryRequest_Shape: confirms the
// outer ConfirmedRequestPDU wrapper + invoke-ID + getNameList
// service tag are present.
func TestBuildMMSGetServerDirectoryRequest_Shape(t *testing.T) {
	pdu := BuildMMSGetServerDirectoryRequest()
	if len(pdu) < 5 {
		t.Fatalf("pdu too short: %d bytes", len(pdu))
	}
	if pdu[0] != 0xA0 {
		t.Errorf("pdu[0] = 0x%02X, want 0xA0 (ConfirmedRequest)", pdu[0])
	}
	// invokeID at offset 2 (after wrapper tag + length)
	if !bytes.Contains(pdu, []byte{0x02, 0x01, 0x01}) {
		t.Errorf("invokeID INTEGER 1 not found in pdu")
	}
	// getNameList service tag 0xA1
	if !bytes.Contains(pdu, []byte{0xA1, 0x0A}) {
		t.Errorf("getNameList service tag 0xA1 not found")
	}
}

// TestParseMMSGetServerDirectoryResponse_Happy: synthetic
// response with 3 LD names → all 3 returned.
func TestParseMMSGetServerDirectoryResponse_Happy(t *testing.T) {
	// Build a synthetic response:
	//   A1 LL                   -- ConfirmedResponse
	//     02 01 01              -- invokeID = 1
	//     A1 LL                 -- getNameList result
	//       A0 LL               -- listOfIdentifier SEQUENCE
	//         1A 03 'L' 'D' '0'
	//         1A 03 'L' 'D' '1'
	//         1A 04 'C', 'T', 'R', 'L'
	//       81 01 00            -- moreFollows = FALSE
	response := []byte{
		0xA1, 0x1B,
		0x02, 0x01, 0x01,
		0xA1, 0x16,
		0xA0, 0x10,
		0x1A, 0x03, 'L', 'D', '0',
		0x1A, 0x03, 'L', 'D', '1',
		0x1A, 0x04, 'C', 'T', 'R', 'L',
		0x81, 0x01, 0x00,
	}
	names, err := ParseMMSGetServerDirectoryResponse(response)
	if err != nil {
		t.Fatalf("parse err: %v", err)
	}
	if len(names) != 3 {
		t.Fatalf("got %d names, want 3: %v", len(names), names)
	}
	want := []string{"LD0", "LD1", "CTRL"}
	for i, w := range want {
		if names[i] != w {
			t.Errorf("names[%d] = %q, want %q", i, names[i], w)
		}
	}
}

// TestParseMMSGetServerDirectoryResponse_TooShort.
func TestParseMMSGetServerDirectoryResponse_TooShort(t *testing.T) {
	_, err := ParseMMSGetServerDirectoryResponse([]byte{0xA1})
	if err == nil {
		t.Errorf("expected ErrShortGetNameListResponse")
	}
}

// TestParseMMSGetServerDirectoryResponse_RejectsNonASCII:
// a "name" with non-printable bytes is dropped.
func TestParseMMSGetServerDirectoryResponse_RejectsNonASCII(t *testing.T) {
	response := []byte{
		0xA1, 0x0E,
		0x02, 0x01, 0x01,
		0xA1, 0x09,
		0xA0, 0x07,
		0x1A, 0x05, 'A', 'B', 0xFF, 'C', 'D',
	}
	names, err := ParseMMSGetServerDirectoryResponse(response)
	if err != nil {
		t.Fatalf("parse err: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("non-ASCII name leaked through: %v", names)
	}
}

// TestFormatLDList_Compact: ≤ 8 names → straight list.
func TestFormatLDList_Compact(t *testing.T) {
	got := FormatLDList([]string{"LD0", "LD1", "CTRL"})
	want := "LDs: [LD0, LD1, CTRL]"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestFormatLDList_Truncated: > 8 names → suffix length.
func TestFormatLDList_Truncated(t *testing.T) {
	names := []string{"LD0", "LD1", "LD2", "LD3", "LD4", "LD5", "LD6", "LD7", "LD8", "LD9"}
	got := FormatLDList(names)
	if !strings.Contains(got, "+2 more") {
		t.Errorf("expected +2 more suffix, got %q", got)
	}
}

// TestFormatLDList_Empty.
func TestFormatLDList_Empty(t *testing.T) {
	if FormatLDList(nil) != "" {
		t.Errorf("empty list should render empty string")
	}
}
