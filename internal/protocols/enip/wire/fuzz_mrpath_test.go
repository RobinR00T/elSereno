package wire

import "testing"

// ParseMRPath parses target-controlled CIP EPATH bytes, including the
// ANSI symbol segment (0x91) added in the 2026-08 audit. It must never
// panic on malformed input.
func FuzzParseMRPath(f *testing.F) {
	f.Add([]byte{0x20, 0x01})                      // class8
	f.Add([]byte{0x21, 0x00, 0x6B, 0x00})          // class16 (Symbol)
	f.Add([]byte{0x91, 0x03, 'A', 'B', 'C', 0x00}) // ANSI symbol segment + pad
	f.Add([]byte{0x91, 0xFF})                      // truncated symbol length
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, path []byte) {
		_, _ = ParseMRPath(path)
	})
}

// ExtractMRService parses the MR request out of a SendRRData /
// SendUnitData body (unconnected 0x00B2 + connected 0x00B1 items). It
// must never panic on malformed input.
func FuzzExtractMRService(f *testing.F) {
	// Unconnected data item carrying Get Attribute Single.
	f.Add([]byte{0, 0, 0, 0, 0x0A, 0x00, 0x01, 0x00, 0xB2, 0x00, 0x06, 0x00, 0x0E, 0x02, 0x20, 0x01, 0x24, 0x01})
	// Connected data item (0x00B1) with a 2-byte sequence prefix.
	f.Add([]byte{0, 0, 0, 0, 0x0A, 0x00, 0x01, 0x00, 0xB1, 0x00, 0x08, 0x00, 0x01, 0x00, 0x0E, 0x02, 0x20, 0x01, 0x24, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, body []byte) {
		_, _, _ = ExtractMRService(body)
	})
}
