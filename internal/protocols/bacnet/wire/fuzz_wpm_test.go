package wire

import "testing"

// ParseWritePropertyMultiple walks a nested, target-controlled APDU
// (the recursion the audit flagged); it must never panic on malformed
// input.
func FuzzParseWritePropertyMultiple(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0c, 0x02, 0x00, 0x00, 0x01})
	f.Add([]byte{0x0c, 0x02, 0x00, 0x00, 0x01, 0x1e, 0x09, 0x55, 0x1f})
	f.Fuzz(func(_ *testing.T, apdu []byte) { _, _ = ParseWritePropertyMultiple(apdu) })
}
