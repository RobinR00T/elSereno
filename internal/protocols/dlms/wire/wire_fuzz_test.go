package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/dlms/wire"
)

// FuzzClassifyResponse asserts that Classify never panics on
// arbitrary input and that the only success paths are valid
// wrapper frames.
func FuzzClassifyResponse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, 0x14, 0x61})
	// 28-byte AARE frame.
	full := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x00, 0x14, 0x61}
	full = append(full, make([]byte, 19)...)
	f.Add(full)
	f.Fuzz(func(t *testing.T, buf []byte) {
		info, err := wire.ClassifyResponse(buf)
		if err != nil {
			return
		}
		if info.APDULen == 0 {
			t.Fatalf("APDULen 0 on success path")
		}
	})
}

// FuzzBuildAARQStable asserts the AARQ probe is always 37
// bytes (8 wrapper + 29 APDU).
func FuzzBuildAARQStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildAARQ()
		if len(got) != 37 {
			t.Fatalf("frame length: got %d want 37", len(got))
		}
		if got[8] != 0x60 {
			t.Fatalf("AARQ tag: got 0x%02x want 0x60", got[8])
		}
	})
}
