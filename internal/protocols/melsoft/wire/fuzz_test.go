package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/melsoft/wire"
)

// FuzzParseCPUInfo asserts ParseCPUInfo never panics on arbitrary input
// and that every success is a real response frame: byte 0 is the 0xD7
// marker with byte 1 == 0x00, and a frame too short for a model yields
// an empty Model. (Model content is sanitised by the plugin, not here.)
func FuzzParseCPUInfo(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xD7, 0x00})
	f.Add(wire.GetCPUInfoRequest)
	seed := make([]byte, wire.MinResponseLen)
	seed[0] = wire.ResponseMarker
	copy(seed[wire.ModelOffset:], []byte("Q03UDECPU"))
	f.Add(seed)
	f.Fuzz(func(t *testing.T, buf []byte) {
		info, err := wire.ParseCPUInfo(buf)
		if err != nil {
			return
		}
		if len(buf) < 2 || buf[0] != wire.ResponseMarker || buf[1] != 0x00 {
			t.Fatalf("success on a non-marker frame: %x", buf)
		}
		if len(buf) < wire.MinResponseLen && info.Model != "" {
			t.Fatalf("model %q on a sub-min frame of len %d", info.Model, len(buf))
		}
	})
}

// FuzzIsResponseFrame asserts IsResponseFrame never panics.
func FuzzIsResponseFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xD7, 0x00})
	f.Fuzz(func(_ *testing.T, buf []byte) {
		_ = wire.IsResponseFrame(buf)
	})
}

// FuzzBuildGetCPUInfoStable asserts the request is always the fixed
// 41-byte getcpuinfopack.
func FuzzBuildGetCPUInfoStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildGetCPUInfo()
		if !bytes.Equal(got, wire.GetCPUInfoRequest) {
			t.Fatalf("BuildGetCPUInfo drifted: %x", got)
		}
	})
}
