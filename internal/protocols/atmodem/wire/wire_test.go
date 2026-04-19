package wire_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/protocols/atmodem/wire"
)

func TestParseSimpleOK(t *testing.T) {
	t.Parallel()
	r, err := wire.Parse([]byte("\r\nOK\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Result != wire.ResultOK {
		t.Fatalf("Result=%q, want OK", r.Result)
	}
}

func TestParseWithBanner(t *testing.T) {
	t.Parallel()
	raw := []byte("ATI\r\nSiemens TC35i\r\nREVISION 04.04\r\n\r\nOK\r\n")
	r, err := wire.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Result != wire.ResultOK {
		t.Fatalf("Result=%q", r.Result)
	}
	if len(r.Lines) < 2 {
		t.Fatalf("Lines=%d, want >=2", len(r.Lines))
	}
}

func TestParseCMEError(t *testing.T) {
	t.Parallel()
	raw := []byte("AT+CPIN?\r\n+CME ERROR: 11\r\n")
	r, err := wire.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Result != wire.ResultCMEError {
		t.Fatalf("Result=%q", r.Result)
	}
	if r.ErrorCode != 11 {
		t.Fatalf("ErrorCode=%d, want 11", r.ErrorCode)
	}
	if !r.IsError() {
		t.Fatal("IsError must be true for CME ERROR")
	}
}

func TestParseConnectWithBaud(t *testing.T) {
	t.Parallel()
	raw := []byte("ATDT3001234567\r\nCONNECT 9600\r\n")
	r, err := wire.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !r.IsConnect() {
		t.Fatalf("IsConnect false; Result=%q", r.Result)
	}
}

func TestReadResponseStopsAtTerminal(t *testing.T) {
	t.Parallel()
	reader := strings.NewReader("ATI\r\nELSERENO-SIM v1\r\nREVISION 1\r\nOK\r\nUNSOLICITED RING\r\n")
	r, err := wire.ReadResponse(reader)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if r.Result != wire.ResultOK {
		t.Fatalf("Result=%q", r.Result)
	}
	if len(r.Lines) != 3 {
		t.Fatalf("Lines=%d, want 3 (echo + 2 body)", len(r.Lines))
	}
}

func TestFingerprintGSM(t *testing.T) {
	t.Parallel()
	f := wire.Detect("", "Siemens\nOK")
	if f.Class != wire.ClassGSM || f.Vendor != wire.VendorSiemens {
		t.Fatalf("Detect: %+v", f)
	}
}

func TestFingerprintLift(t *testing.T) {
	t.Parallel()
	f := wire.Detect("KONE KCE-5500 lift-interphone", "")
	if f.Class != wire.ClassLift || f.Vendor != wire.VendorKoneLift {
		t.Fatalf("Detect: %+v", f)
	}
}

func TestParseRejectsHugeResponse(t *testing.T) {
	t.Parallel()
	raw := make([]byte, wire.MaxResponseBytes+1)
	for i := range raw {
		raw[i] = 'a'
	}
	_, err := wire.Parse(raw)
	if err == nil {
		t.Fatal("expected ErrTooLong")
	}
}
