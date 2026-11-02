package wire_test

import (
	"bufio"
	"bytes"
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

// The write-gate and refusal paths parse application data a client
// sends through the proxy: no input may panic them.
func FuzzExtractObjects(f *testing.F) {
	f.Add([]byte{0xC0, 0x05, 0x0C, 0x01, 0x17, 0x01, 0x00, 0x03, 0x01, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0xC0, 0x05, 0x29, 0x02, 0x28, 0x01, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ExtractCROBs(b)
		_, _ = wire.ExtractAnalogOutputs(b)
		_, _, _ = wire.ExtractControlObjects(b)
		_, _, _ = wire.ParseIIN(b)
		_, _ = wire.StripBlockCRCs(b, len(b)/2)
	})
}

func FuzzReadFrame(f *testing.F) {
	f.Add(wire.BuildRequestLinkStatus(1, 2))
	f.Add(append(wire.BuildRequestLinkStatus(1, 2), 0x05, 0x64, 0xFF))
	f.Fuzz(func(_ *testing.T, b []byte) {
		r := bufio.NewReader(bytes.NewReader(b))
		for i := 0; i < 8; i++ {
			if _, _, _, _, err := wire.ReadFrame(r); err != nil {
				return
			}
		}
	})
}
