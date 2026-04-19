package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/hartip/wire"
)

func FuzzParseHeader(f *testing.F) {
	f.Add(wire.BuildSessionInitiate(0))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ParseHeader(b)
	})
}
