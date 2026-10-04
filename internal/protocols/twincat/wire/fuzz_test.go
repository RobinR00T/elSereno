package wire

import (
	"encoding/hex"
	"testing"
)

// FuzzParseDeviceInfo asserts the ADS ReadDeviceInfo parser never panics on
// arbitrary input off TCP/48898. The AMS/TCP + AMS routing header carry
// attacker-controlled length and data-length fields, so a malformed frame
// must be rejected, never crash. Seeded with the real TwinCAT 2 response
// from realcap_test.go.
func FuzzParseDeviceInfo(f *testing.F) {
	if seed, err := hex.DecodeString(realReadDeviceInfoResp); err == nil {
		f.Add(seed)
	}
	f.Add([]byte{})
	f.Add(make([]byte, FrameMinLen))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = ParseDeviceInfo(b)
	})
}
