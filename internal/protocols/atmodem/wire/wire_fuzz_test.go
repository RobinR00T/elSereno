package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/atmodem/wire"
)

// FuzzParseResponse asserts that Parse never panics and that, when
// it succeeds, the returned Result is one of the recognised codes
// or ResultUnknown; nothing else is allowed.
func FuzzParseResponse(f *testing.F) {
	f.Add([]byte("OK\r\n"))
	f.Add([]byte("\r\nATI\r\nSiemens TC35i\r\nOK\r\n"))
	f.Add([]byte("+CME ERROR: 10\r\n"))
	f.Add([]byte("CONNECT 9600\r\n"))
	f.Add([]byte("NO CARRIER\r\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > wire.MaxResponseBytes {
			return
		}
		r, err := wire.Parse(raw)
		if err != nil {
			return
		}
		switch r.Result {
		case wire.ResultOK, wire.ResultError, wire.ResultConnect,
			wire.ResultNoCarrier, wire.ResultNoDialtone, wire.ResultBusy,
			wire.ResultNoAnswer, wire.ResultRing, wire.ResultCMEError,
			wire.ResultCMSError, wire.ResultUnknown:
			// ok
		default:
			t.Fatalf("unexpected Result %q", r.Result)
		}
	})
}

// FuzzDetect asserts the fingerprint detector never panics and
// always returns one of the declared Class values.
func FuzzDetect(f *testing.F) {
	f.Add("Siemens TC35i", "")
	f.Add("KONE lift", "KONE")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, banner, cgmi string) {
		fp := wire.Detect(banner, cgmi)
		switch fp.Class {
		case wire.ClassGSM, wire.ClassHayes, wire.ClassLift, wire.ClassUnknown:
			// ok
		default:
			t.Fatalf("unexpected Class %q", fp.Class)
		}
	})
}
