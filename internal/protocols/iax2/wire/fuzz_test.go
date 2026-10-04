package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/iax2/wire"
)

// FuzzParseHeader asserts the IAX2 full-frame header parser never panics on
// arbitrary input off UDP/4569 and that IsIAXReply is safe on any header it
// returns. Seeded with the real incoming NEW frame from realcap_test.go.
func FuzzParseHeader(f *testing.F) {
	if seed, err := hex.DecodeString(realNEW); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add(make([]byte, wire.HeaderLen))
	f.Fuzz(func(_ *testing.T, b []byte) {
		h, err := wire.ParseHeader(b)
		if err == nil {
			_ = h.IsIAXReply()
		}
	})
}
