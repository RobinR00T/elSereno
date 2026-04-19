package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/s7/wire"
)

func TestTPKTRoundTrip(t *testing.T) {
	t.Parallel()
	cotp := wire.BuildCOTPConnectionRequest()
	var buf bytes.Buffer
	if err := wire.WriteTPKT(&buf, cotp); err != nil {
		t.Fatalf("WriteTPKT: %v", err)
	}
	got, err := wire.ReadTPKT(&buf)
	if err != nil {
		t.Fatalf("ReadTPKT: %v", err)
	}
	if got.Version != wire.TPKTVersion {
		t.Fatalf("Version=0x%02x", got.Version)
	}
	if !bytes.Equal(got.Payload, cotp) {
		t.Fatalf("payload mismatch")
	}
}

func TestTPKTRejectsBadVersion(t *testing.T) {
	t.Parallel()
	b := []byte{0x04, 0x00, 0x00, 0x07, 0xFF, 0xFF, 0xFF}
	_, err := wire.ParseTPKT(b)
	if !errors.Is(err, wire.ErrBadTPKT) {
		t.Fatalf("got %v, want ErrBadTPKT", err)
	}
}

func TestTPKTRejectsShortLength(t *testing.T) {
	t.Parallel()
	b := []byte{0x03, 0x00, 0x00, 0x03}
	_, err := wire.ParseTPKT(b)
	if !errors.Is(err, wire.ErrBadTPKT) {
		t.Fatalf("got %v, want ErrBadTPKT", err)
	}
}

func TestCOTPConfirmDetect(t *testing.T) {
	t.Parallel()
	cc := []byte{0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00}
	if !wire.IsCOTPConfirm(cc) {
		t.Fatal("IsCOTPConfirm failed for a CC PDU")
	}
	cr := wire.BuildCOTPConnectionRequest()
	if wire.IsCOTPConfirm(cr) {
		t.Fatal("IsCOTPConfirm true for a CR")
	}
}
