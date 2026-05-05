package wire_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/protocols/mms/wire"
)

// TestMMSApplicationContextOIDBytes — pin the BER encoding
// of the IEC 61850-8-1 application-context-name OID. A
// regression here means we'd send the wrong OID in the
// AARQ, and real MMS servers would reject the
// association.
//
// 1.0.9506.2.3 BER-encodes as:
//
//	first two components 1.0  → 1*40+0  = 0x28
//	9506                       → 0xCA 0x22 (varlen subid)
//	2                          → 0x02
//	3                          → 0x03
func TestMMSApplicationContextOIDBytes(t *testing.T) {
	want := []byte{0x28, 0xCA, 0x22, 0x02, 0x03}
	if len(wire.MMSApplicationContextOID) != len(want) {
		t.Fatalf("OID len = %d, want %d", len(wire.MMSApplicationContextOID), len(want))
	}
	for i, b := range want {
		if wire.MMSApplicationContextOID[i] != b {
			t.Errorf("OID[%d] = 0x%02x, want 0x%02x", i, wire.MMSApplicationContextOID[i], b)
		}
	}
}

// TestBuildACSEAssociateRequestMMS — the static AARQ frame
// must be non-empty + must contain the IEC 61850-8-1 OID
// (so any future refactor that loses the OID gets caught
// at test time).
func TestBuildACSEAssociateRequestMMS(t *testing.T) {
	frame := wire.BuildACSEAssociateRequestMMS()
	if len(frame) < 64 {
		t.Errorf("AARQ too short: %d bytes", len(frame))
	}
	// The OID must appear at least twice — once in the
	// presentation context-definition (abstract syntax)
	// and once in the AARQ application-context-name.
	count := 0
	for i := 0; i+5 <= len(frame); i++ {
		if frame[i] == 0x28 && frame[i+1] == 0xCA && frame[i+2] == 0x22 &&
			frame[i+3] == 0x02 && frame[i+4] == 0x03 {
			count++
		}
	}
	if count < 1 {
		t.Errorf("AARQ does not contain IEC 61850-8-1 OID:\n%x", frame)
	}
}

// TestParseACSEAssociateResponseMMS_Positive — a buffer
// containing the OID anywhere returns nil.
func TestParseACSEAssociateResponseMMS_Positive(t *testing.T) {
	// COTP DT (3 bytes) + arbitrary preamble + OID + tail.
	// The scan must find the OID irrespective of position.
	resp := []byte{
		0x02, 0xF0, 0x80, // COTP DT header
		0xDE, 0xAD, 0xBE, 0xEF, // junk
		0x28, 0xCA, 0x22, 0x02, 0x03, // OID
		0xCA, 0xFE, // tail
	}
	if err := wire.ParseACSEAssociateResponseMMS(resp); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

// TestParseACSEAssociateResponseMMS_NoOID — a long buffer
// without the OID returns ErrNoMMSACSEResponse.
func TestParseACSEAssociateResponseMMS_NoOID(t *testing.T) {
	resp := make([]byte, 256)
	for i := range resp {
		resp[i] = 0xFF
	}
	err := wire.ParseACSEAssociateResponseMMS(resp)
	if !errors.Is(err, wire.ErrNoMMSACSEResponse) {
		t.Errorf("err = %v, want ErrNoMMSACSEResponse", err)
	}
}

// TestParseACSEAssociateResponseMMS_TooShort — a buffer
// shorter than COTP-DT-header + OID-len returns
// ErrACSETooShort.
func TestParseACSEAssociateResponseMMS_TooShort(t *testing.T) {
	resp := []byte{0x02, 0xF0, 0x80, 0xCA, 0xFE}
	err := wire.ParseACSEAssociateResponseMMS(resp)
	if !errors.Is(err, wire.ErrACSETooShort) {
		t.Errorf("err = %v, want ErrACSETooShort", err)
	}
}

// TestParseACSEAssociateResponseMMS_OIDAtBoundary — OID
// at the very start (just after a 3-byte preamble) is
// found.
func TestParseACSEAssociateResponseMMS_OIDAtBoundary(t *testing.T) {
	resp := []byte{
		0x02, 0xF0, 0x80,
		0x28, 0xCA, 0x22, 0x02, 0x03,
	}
	if err := wire.ParseACSEAssociateResponseMMS(resp); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

// TestParseACSEAssociateResponseMMS_PartialOID — a buffer
// with 4 of the 5 OID bytes (missing the last) does NOT
// match.
func TestParseACSEAssociateResponseMMS_PartialOID(t *testing.T) {
	resp := []byte{
		0x02, 0xF0, 0x80,
		0xDE, 0xAD,
		0x28, 0xCA, 0x22, 0x02, // missing 0x03
		0xCA, 0xFE,
	}
	err := wire.ParseACSEAssociateResponseMMS(resp)
	if !errors.Is(err, wire.ErrNoMMSACSEResponse) {
		t.Errorf("err = %v, want ErrNoMMSACSEResponse on partial OID", err)
	}
}
