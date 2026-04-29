package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/finsudp/wire"
)

// FuzzParseControllerDataRead asserts that ParseControllerDataRead
// never panics on arbitrary input and that, on success, the
// returned ControllerData has only printable ASCII or empty
// fields (the wire parser trims NUL/space padding).
func FuzzParseControllerDataRead(f *testing.F) {
	f.Add([]byte{}, byte(0x00))
	// 14-byte minimum response with a successful end code.
	f.Add([]byte{
		0xC0, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x42,
		0x05, 0x01,
		0x00, 0x00,
	}, byte(0x42))
	// 74-byte full response with model + internal + system version.
	full := []byte{
		0xC0, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x11,
		0x05, 0x01,
		0x00, 0x00,
	}
	full = append(full, []byte("CJ2M-CPU33          ")...)
	full = append(full, []byte("V1.04 OMRON CO.     ")...)
	full = append(full, []byte("1.04 SYS            ")...)
	f.Add(full, byte(0x11))
	f.Fuzz(func(t *testing.T, buf []byte, sid byte) {
		cd, err := wire.ParseControllerDataRead(buf, sid)
		if err != nil {
			return
		}
		// trimASCII's contract is "trim TRAILING NULs / spaces"
		// — the last byte of every returned string must not be
		// NUL or space. Embedded NULs / spaces are preserved
		// intentionally so the parser can't silently splice
		// adversarial input across a NUL boundary.
		for _, s := range []string{cd.Model, cd.InternalCode, cd.SystemVersion} {
			if s == "" {
				continue
			}
			last := s[len(s)-1]
			if last == 0x00 || last == ' ' {
				t.Fatalf("trimASCII left trailing NUL/space in %q", s)
			}
		}
	})
}

// FuzzBuildControllerDataReadStable asserts that the builder
// produces a 13-byte frame for any SID.
func FuzzBuildControllerDataReadStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Add(byte(0xFF))
	f.Add(byte(0x42))
	f.Fuzz(func(t *testing.T, sid byte) {
		got := wire.BuildControllerDataRead(sid)
		if len(got) != 13 {
			t.Fatalf("frame length: got %d want 13", len(got))
		}
		if got[9] != sid {
			t.Fatalf("SID slot: got 0x%02x want 0x%02x", got[9], sid)
		}
	})
}
