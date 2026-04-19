package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/iec104/wire"
)

func FuzzParseAPCI(f *testing.F) {
	f.Add(wire.BuildTESTFR())
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ParseAPCI(b)
	})
}
