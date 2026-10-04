package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/proconos/wire"
)

// FuzzClassify asserts the ProConOS response classifier never panics on
// arbitrary bytes off TCP/20547 and that IsProConOSFrame agrees on the
// signature path. Seeded with a 0xcc-signature response, the probe request,
// and a banner-bearing buffer.
func FuzzClassify(f *testing.F) {
	sig := make([]byte, 80)
	sig[0] = 0xcc
	f.Add(sig)
	f.Add(wire.BuildHello())
	f.Add([]byte("\x00\x00\x00\x00ProConOS V5.0.0.40"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, err := wire.Classify(b)
		if is := wire.IsProConOSFrame(b); is && err != nil {
			t.Fatalf("IsProConOSFrame=true but Classify errored: %v", err)
		}
	})
}
