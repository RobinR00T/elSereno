package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/codesys/wire"
)

// FuzzClassify asserts that Classify never panics on arbitrary
// input and that, on success, the returned note is non-empty.
func FuzzClassify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("HTTP/1.1 200 OK"))
	f.Add(append([]byte{0xCD, 0xCD, 0xCD, 0xCD}, []byte(" payload")...))
	f.Add([]byte("\x00\x00\x00 CoDeSys V3 SP19 \n"))
	f.Fuzz(func(t *testing.T, buf []byte) {
		note, err := wire.Classify(buf)
		if err != nil {
			return
		}
		if note == "" {
			t.Fatalf("empty note on success path; buf=%x", buf)
		}
	})
}

// FuzzBuildHelloStable asserts the hello is always exactly the
// 4-byte BlockDriver magic.
func FuzzBuildHelloStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildHello()
		if len(got) != 4 {
			t.Fatalf("frame length: got %d want 4", len(got))
		}
		for i, b := range got {
			if b != 0xCD {
				t.Fatalf("byte %d: got 0x%02x want 0xCD", i, b)
			}
		}
	})
}
