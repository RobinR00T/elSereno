package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/mms/wire"
)

// FuzzReadTPKT drives wire.ReadTPKT with arbitrary inputs to
// surface panics on:
//   - byte-length boundary edges (0..3 bytes)
//   - claimed lengths that exceed the actual buffer
//   - claimed lengths under MinTPKTLen
//   - truncated TPKTs from the middle of a real handshake
func FuzzReadTPKT(f *testing.F) {
	// Seed: a real CC envelope.
	var seed bytes.Buffer
	_ = wire.WriteTPKT(&seed, []byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00})
	f.Add(seed.Bytes())
	f.Add([]byte{})
	f.Add([]byte{0x03})
	f.Add([]byte{0x03, 0x00, 0xff, 0xff})
	f.Add([]byte{0x03, 0x00, 0x00, 0x05})

	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = wire.ReadTPKT(bytes.NewReader(raw))
	})
}

// FuzzClassifyCOTP exercises the COTP-classifier surface; should
// never panic on arbitrary buffers.
func FuzzClassifyCOTP(f *testing.F) {
	f.Add([]byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00})
	f.Add([]byte{0x06, 0x80, 0x00, 0x01, 0x00, 0x01, 0x01})
	f.Add([]byte{0x01})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		note, err := wire.ClassifyCOTP(raw)
		if err != nil && note != "" {
			t.Errorf("err=%v but note=%q", err, note)
		}
	})
}
