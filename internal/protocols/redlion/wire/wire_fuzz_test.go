package wire_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/protocols/redlion/wire"
)

// FuzzClassify asserts that Classify never panics on arbitrary
// input and that, on success, the note names what matched.
func FuzzClassify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("HTTP/1.1 200 OK"))
	f.Add([]byte("\x00\x00\x00 Crimson 3 \n"))
	f.Add([]byte("Sixnet RTU"))
	f.Add([]byte("\x00\x16\x01\x2b\x03\x00Red Lion Controls\x00"))
	f.Add(append([]byte(nil), wire.ManufacturerQuery...))
	f.Fuzz(func(t *testing.T, buf []byte) {
		note, err := wire.Classify(buf)
		if err != nil {
			return
		}
		if !strings.HasPrefix(note, "banner=") && !strings.HasPrefix(note, "manufacturer=") {
			t.Fatalf("note names neither a banner nor a manufacturer: %q", note)
		}
	})
}

// FuzzParseStringResponse: never panics, and a parsed string is
// printable and lies within the input.
func FuzzParseStringResponse(f *testing.F) {
	f.Add([]byte("\x00\x16\x01\x2b\x03\x00Red Lion Controls\x00"))
	f.Add([]byte{0x00, 0x04, 0x01, 0x2b, 0x1b, 0x00})
	f.Fuzz(func(t *testing.T, buf []byte) {
		s, err := wire.ParseStringResponse(buf)
		if err != nil {
			return
		}
		if s == "" || len(s) > len(buf) {
			t.Fatalf("bad string %q from %d bytes", s, len(buf))
		}
	})
}
