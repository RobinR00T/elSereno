package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

func FuzzParseHeader(f *testing.F) {
	f.Add(wire.BuildReadClass0(1, 2))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ParseHeader(b)
	})
}
