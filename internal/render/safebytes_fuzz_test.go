package render_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"local/elsereno/internal/render"
)

// FuzzSafeBytes: target-controlled bytes never produce escape sequences
// or raw C0 control characters (except TAB/LF, which SafeBytes preserves
// as-is by design) in the output.
func FuzzSafeBytes(f *testing.F) {
	seeds := [][]byte{
		nil, {},
		[]byte("hello"),
		[]byte("line1\nline2"),
		[]byte("tab\there"),
		{0x00, 0x01, 0x02, 0x03},
		{0x1B, '[', '3', '1', 'm', 'R', 'E', 'D'},
		{0xFF, 0xFE, 0xFD},
		{0x80, 0x81, 0x82},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		out := render.SafeBytes(raw)
		if !utf8.ValidString(out) {
			t.Fatalf("SafeBytes produced invalid UTF-8 for %q", raw)
		}
		if strings.ContainsRune(out, '\x1b') {
			t.Fatalf("SafeBytes leaked ESC (0x1B) into %q", out)
		}
		for _, r := range out {
			if r != '\t' && r != '\n' && r < 0x20 {
				t.Fatalf("SafeBytes leaked C0 control U+%04X into %q", r, out)
			}
			if r == 0x7F {
				t.Fatalf("SafeBytes leaked DEL into %q", out)
			}
			if r >= 0x80 && r <= 0x9F {
				t.Fatalf("SafeBytes leaked C1 U+%04X into %q", r, out)
			}
		}
	})
}
