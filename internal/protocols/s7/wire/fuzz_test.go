package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/s7/wire"
)

// FuzzParseTPKT asserts ParseTPKT never panics and that, on success,
// Version == 0x03 and Length is in [MinTPKTLen, MaxTPKTLen].
func FuzzParseTPKT(f *testing.F) {
	f.Add([]byte{0x03, 0x00, 0x00, 0x07, 0xE0, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		tp, err := wire.ParseTPKT(b)
		if err != nil {
			return
		}
		if tp.Version != wire.TPKTVersion {
			t.Fatalf("Version=%d", tp.Version)
		}
		if tp.Length < wire.MinTPKTLen || tp.Length > wire.MaxTPKTLen {
			t.Fatalf("Length=%d out of range", tp.Length)
		}
	})
}
