package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/mms/wire"
)

func TestBuildCOTPConnectionRequestMMS_Shape(t *testing.T) {
	frame := wire.BuildCOTPConnectionRequestMMS()
	// LI byte at offset 0 should equal len(frame)-1.
	if int(frame[0]) != len(frame)-1 {
		t.Errorf("LI=%d, want %d (= len-1)", frame[0], len(frame)-1)
	}
	// PDU type at offset 1 must be CR (0xE0).
	if frame[1] != wire.COTPConnectionRequest {
		t.Errorf("PDU type = 0x%02x, want 0xE0 (CR)", frame[1])
	}
	// Source TSAP at offset 7..10: 0xC1 0x02 0x00 0x01.
	if !bytes.Equal(frame[7:11], []byte{0xC1, 0x02, 0x00, 0x01}) {
		t.Errorf("source TSAP = % x, want C1 02 00 01", frame[7:11])
	}
	// Destination TSAP at offset 11..14: 0xC2 0x02 0x00 0x01.
	if !bytes.Equal(frame[11:15], []byte{0xC2, 0x02, 0x00, 0x01}) {
		t.Errorf("dest TSAP = % x, want C2 02 00 01", frame[11:15])
	}
}

func TestRoundTripTPKT(t *testing.T) {
	payload := wire.BuildCOTPConnectionRequestMMS()
	var buf bytes.Buffer
	if err := wire.WriteTPKT(&buf, payload); err != nil {
		t.Fatalf("WriteTPKT: %v", err)
	}
	got, err := wire.ReadTPKT(&buf)
	if err != nil {
		t.Fatalf("ReadTPKT: %v", err)
	}
	if got.Version != wire.TPKTVersion {
		t.Errorf("version = 0x%02x, want 0x03", got.Version)
	}
	if int(got.Length) != wire.TPKTHeaderLen+len(payload) {
		t.Errorf("length = %d, want %d", got.Length, wire.TPKTHeaderLen+len(payload))
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload mismatch: % x vs % x", got.Payload, payload)
	}
}

func TestClassifyCOTP_Confirm(t *testing.T) {
	// COTP CC: LI + 0xD0 + DstRef + SrcRef + Class.
	cc := []byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00}
	note, err := wire.ClassifyCOTP(cc)
	if err != nil {
		t.Fatalf("ClassifyCOTP CC: %v", err)
	}
	if note == "" {
		t.Errorf("expected non-empty note for CC")
	}
}

func TestClassifyCOTP_Disconnect(t *testing.T) {
	// COTP DR: LI + 0x80 + DstRef + SrcRef + Reason.
	dr := []byte{0x06, 0x80, 0x00, 0x01, 0x00, 0x01, 0x01}
	_, err := wire.ClassifyCOTP(dr)
	if !errors.Is(err, wire.ErrNotCOTPConfirm) {
		t.Fatalf("err = %v, want ErrNotCOTPConfirm", err)
	}
}

func TestClassifyCOTP_Short(t *testing.T) {
	_, err := wire.ClassifyCOTP([]byte{0x01})
	if !errors.Is(err, wire.ErrShortCOTP) {
		t.Fatalf("err = %v, want ErrShortCOTP", err)
	}
}

func TestIsCOTPConfirm_DiscriminatesPDUTypes(t *testing.T) {
	if !wire.IsCOTPConfirm([]byte{0x06, 0xD0, 0x00}) {
		t.Error("CC byte not recognised")
	}
	if wire.IsCOTPConfirm([]byte{0x06, 0x80, 0x00}) {
		t.Error("DR misidentified as CC")
	}
	if wire.IsCOTPConfirm([]byte{0x01}) {
		t.Error("short buffer accepted")
	}
}

func TestIsCOTPDisconnect_DiscriminatesPDUTypes(t *testing.T) {
	if !wire.IsCOTPDisconnect([]byte{0x06, 0x80, 0x00}) {
		t.Error("DR byte not recognised")
	}
	if wire.IsCOTPDisconnect([]byte{0x06, 0xD0, 0x00}) {
		t.Error("CC misidentified as DR")
	}
}

func TestReadTPKT_BadVersion(t *testing.T) {
	var buf bytes.Buffer
	// Bad version byte.
	buf.Write([]byte{0xFF, 0x00, 0x00, 0x07, 0x06, 0xD0, 0x00})
	_, err := wire.ReadTPKT(&buf)
	if !errors.Is(err, wire.ErrBadTPKT) {
		t.Fatalf("err = %v, want ErrBadTPKT", err)
	}
}

func TestReadTPKT_TooShort(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x03, 0x00, 0x00, 0x05}) // header announces length 5 < MinTPKTLen
	_, err := wire.ReadTPKT(&buf)
	if !errors.Is(err, wire.ErrBadTPKT) {
		t.Fatalf("err = %v, want ErrBadTPKT", err)
	}
}
