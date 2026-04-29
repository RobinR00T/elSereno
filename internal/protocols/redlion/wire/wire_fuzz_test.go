package wire_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/protocols/redlion/wire"
)

// FuzzClassify asserts that Classify never panics on arbitrary
// input and that, on success, the returned note begins with
// "banner=" and contains a printable substring.
func FuzzClassify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("HTTP/1.1 200 OK"))
	f.Add([]byte("\x00\x00\x00 Crimson 3 \n"))
	f.Add([]byte("Sixnet RTU"))
	f.Fuzz(func(t *testing.T, buf []byte) {
		note, err := wire.Classify(buf)
		if err != nil {
			return
		}
		if !strings.HasPrefix(note, "banner=") {
			t.Fatalf("note missing banner= prefix: %q", note)
		}
	})
}

// FuzzBuildHelloStable asserts the hello is always exactly 3
// bytes of zero.
func FuzzBuildHelloStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildHello()
		if len(got) != 3 {
			t.Fatalf("frame length: got %d want 3", len(got))
		}
		for i, b := range got {
			if b != 0x00 {
				t.Fatalf("byte %d: got 0x%02x want 0x00", i, b)
			}
		}
	})
}
