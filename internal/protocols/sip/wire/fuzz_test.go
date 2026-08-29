package wire

import (
	"bytes"
	"testing"
)

// ParseResponse reads a target-controlled SIP response; it must never
// panic on malformed input.
func FuzzParseResponse(f *testing.F) {
	f.Add([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("SIP/2.0 486 Busy Here\r\n\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseResponse(bytes.NewReader(b)) })
}
