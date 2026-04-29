package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/knxip/wire"
)

// FuzzParseDescriptionResponse asserts that
// ParseDescriptionResponse never panics on arbitrary input and
// that, on success, the FriendlyName has no TRAILING NUL or
// space (trimASCII's contract — embedded bytes preserved on
// purpose so attacker-controlled NUL-splice input doesn't get
// silently merged into a shorter benign string).
func FuzzParseDescriptionResponse(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 60))
	// 60-byte success response with "Gira" friendly name.
	resp := make([]byte, 60)
	resp[0] = 0x06
	resp[1] = 0x10
	resp[2] = 0x02
	resp[3] = 0x05
	resp[4] = 0x00
	resp[5] = 0x3C
	resp[6] = 0x36
	resp[7] = 0x01
	resp[8] = 0x02
	resp[10] = 0x11
	resp[11] = 0x01
	copy(resp[30:60], []byte("Gira"))
	f.Add(resp)
	f.Fuzz(func(t *testing.T, buf []byte) {
		di, err := wire.ParseDescriptionResponse(buf)
		if err != nil {
			return
		}
		if di.FriendlyName == "" {
			return
		}
		last := di.FriendlyName[len(di.FriendlyName)-1]
		if last == 0x00 || last == ' ' {
			t.Fatalf("trimASCII left trailing NUL/space in FriendlyName=%q", di.FriendlyName)
		}
	})
}

// FuzzBuildDescriptionRequestStable asserts the builder
// produces a 14-byte frame regardless of fuzz input.
func FuzzBuildDescriptionRequestStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildDescriptionRequest()
		if len(got) != 14 {
			t.Fatalf("frame length: got %d want 14", len(got))
		}
		if got[0] != 0x06 || got[1] != 0x10 {
			t.Fatalf("header bytes: got 0x%02x 0x%02x want 0x06 0x10", got[0], got[1])
		}
	})
}
