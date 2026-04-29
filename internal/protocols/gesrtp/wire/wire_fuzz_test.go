package wire_test

import (
	"strings"
	"testing"
	"unicode"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

// FuzzClassifyResponse asserts that ClassifyResponse never panics
// on arbitrary input and that the only success path is a 56-byte
// (or longer) buffer with byte 0 = 0x03.
func FuzzClassifyResponse(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 56))
	resp := make([]byte, 56)
	resp[0] = 0x03
	f.Add(resp)
	f.Fuzz(func(t *testing.T, buf []byte) {
		err := wire.ClassifyResponse(buf)
		if err != nil {
			return
		}
		if len(buf) < 56 {
			t.Fatalf("ClassifyResponse passed on len=%d (must be >=56)", len(buf))
		}
		if buf[0] != 0x03 {
			t.Fatalf("ClassifyResponse passed with type byte 0x%02x (must be 0x03)", buf[0])
		}
	})
}

// FuzzExtractModelHint asserts that ExtractModelHint never
// panics on arbitrary input and that any returned hint:
//   - has at least 5 ASCII characters,
//   - starts with one of the canonical GE PLC family prefixes,
//   - contains only printable letters / digits / dashes /
//     underscores (no NUL, no control bytes).
func FuzzExtractModelHint(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("IC693CPU374"))
	f.Add(append(make([]byte, 16), []byte("PACSystems_RX3i\x00")...))
	f.Add([]byte("\x00\x00ABC"))
	f.Fuzz(func(t *testing.T, buf []byte) {
		hint := wire.ExtractModelHint(buf)
		if hint == "" {
			return
		}
		if len(hint) < 5 {
			t.Fatalf("hint too short: %q", hint)
		}
		// Validate the hint starts with a canonical prefix by
		// trying every one. (We can't import the unexported
		// list; just check the well-known literals.)
		matched := false
		for _, pfx := range []string{"PACSystems", "IC693", "IC695", "IC697", "IC200", "RX3i", "RX7i"} {
			if strings.HasPrefix(hint, pfx) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("hint %q matches no canonical GE PLC prefix", hint)
		}
		// Validate every byte is letter / digit / dash /
		// underscore.
		for i, r := range hint {
			ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_'
			if !ok {
				t.Fatalf("hint %q has non-modelByte at offset %d: %q", hint, i, r)
			}
		}
	})
}
