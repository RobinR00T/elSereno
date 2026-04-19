package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/enip/wire"
)

func FuzzParseHeader(f *testing.F) {
	f.Add(make([]byte, wire.HeaderLen))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := wire.ParseHeader(b)
		if err != nil {
			return
		}
		if h.Length > wire.MaxBodyLen {
			t.Fatalf("Length=%d", h.Length)
		}
	})
}

func FuzzParseListIdentity(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ParseListIdentity(b)
	})
}
