package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/bacnet/wire"
)

func FuzzParseBVLC(f *testing.F) {
	f.Add(wire.BuildWhoIs())
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ParseBVLC(b)
	})
}
