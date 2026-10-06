package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

func FuzzParseHeader(f *testing.F) {
	f.Add(wire.BuildRequestLinkStatus(1, 2))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ParseHeader(b)
		_ = wire.ValidHeader(b)
	})
}
