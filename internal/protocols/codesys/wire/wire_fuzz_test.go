package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/codesys/wire"
)

// FuzzClassify asserts that Classify never panics on arbitrary
// input and that, on success, the returned note is non-empty.
func FuzzClassify(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("HTTP/1.1 200 OK"))
	// Real Block Driver magic 00 01 17 e8 (0xE8170100 LE), PITF-068.
	f.Add(append([]byte{0x00, 0x01, 0x17, 0xE8}, []byte(" payload")...))
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
// 4-byte Block Driver magic (0xE8170100 LE: 00 01 17 e8).
func FuzzBuildHelloStable(f *testing.F) {
	f.Add(byte(0x00))
	want := []byte{0x00, 0x01, 0x17, 0xE8}
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildHello()
		if !bytes.Equal(got, want) {
			t.Fatalf("hello: got %x want %x", got, want)
		}
	})
}
