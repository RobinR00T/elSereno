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

// The Read/Browse walkers and the NodeId formatter also take
// target-controlled bytes (the writeable-tag walk reads them from the
// live server) and must never panic, hang or blow memory on malformed
// input. The array-length caps + bounds-checked cursor are the guard.

func FuzzParseReadResponse(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseReadResponse(b) })
}

func FuzzParseBrowseResponse(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseBrowseResponse(b) })
}

func FuzzNodeIDText(f *testing.F) {
	f.Add([]byte{0x00, 0x55})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _ = NodeIDText(b) })
}
