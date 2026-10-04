package profinet_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/profinet"
)

// FuzzDecodeDCP asserts the PROFINET DCP decoder never panics on arbitrary
// input and that ParseIdentifyResponse is safe to run on whatever DecodeDCP
// returns. DCP runs directly over Ethernet (untrusted L2 input), so a
// malformed block stream must be rejected, never crash. Seeded with the real
// DCP Identify response from realcap_test.go (bytes after the Ethernet
// header, which is what DecodeDCP consumes).
func FuzzDecodeDCP(f *testing.F) {
	if seed, err := hex.DecodeString(realIdentifyResponse); err == nil && len(seed) > 14 {
		f.Add(seed[14:])
	}
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(_ *testing.T, b []byte) {
		fr, err := profinet.DecodeDCP(b)
		if err == nil && fr != nil {
			_ = profinet.ParseIdentifyResponse(fr)
		}
	})
}
