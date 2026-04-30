package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/pcworx/wire"
)

// FuzzClassify drives wire.Classify with arbitrary inputs to
// surface panics on:
//   - byte-length boundary edges (0, 1, 2, 3 bytes)
//   - over-long inputs that include the PCWorx prefix at random
//     offsets (only a leading match counts)
//   - inputs containing partial banner substrings
//
// Catches the same class of bugs the v1.20 + v1.21 wire fuzzers
// caught (slmp `FF FF FF FF` / finsudp truncated FINS responder).
func FuzzClassify(f *testing.F) {
	// Seed corpus with the canonical hello + a few synthetic
	// banners.
	f.Add([]byte{0x01, 0x01, 0x00, 0x1C})
	f.Add([]byte("Phoenix Contact ILC 350 PN"))
	f.Add([]byte("ProConOS V5.0.0.40"))
	f.Add([]byte("HTTP/1.1 400 Bad Request"))
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, buf []byte) {
		note, err := wire.Classify(buf)
		// Either err is a sentinel and note is empty, OR err is
		// nil and note is non-empty. Anything else is a bug.
		if err != nil && note != "" {
			t.Errorf("err=%v but note=%q (expected empty note on error)", err, note)
		}
		if err == nil && note == "" {
			t.Errorf("err=nil but note empty (expected non-empty note on success)")
		}
	})
}
