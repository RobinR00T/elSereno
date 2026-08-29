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

// The WriteRequest / CallRequest walkers read an attacker-controlled
// array length and presize a slice with it; they must not panic or
// blow memory on malformed input (regression for the arrLen OOM).

func FuzzWriteRequestAllNodesRich(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = WriteRequestAllNodesRich(b) })
}

func FuzzWriteRequestAllNodes(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = WriteRequestAllNodes(b) })
}

func FuzzCallRequestAllMethods(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = CallRequestAllMethods(b) })
}
