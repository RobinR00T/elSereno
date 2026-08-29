package wire

import "testing"

// The OPC-UA message parsers take target-controlled bytes and must
// never panic on malformed input.

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte("HELF\x1c\x00\x00\x00"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseHeader(b) })
}

func FuzzParseAcknowledge(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseAcknowledge(b) })
}

func FuzzParseError(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseError(b) })
}
