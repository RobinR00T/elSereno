package render_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/render"
)

func TestSafeBytes(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"ascii", []byte("hello"), "hello"},
		{"tab_and_newline_preserved", []byte("a\tb\nc"), "a\tb\nc"},
		{"null_to_picture", []byte("a\x00b"), "a\u2400b"},
		{"escape_to_picture", []byte("a\x1bb"), "a\u241bb"},
		{"del_to_picture", []byte("a\x7fb"), "a\u2421b"},
		{"c1_to_replacement", []byte{'a', 0x80, 'b'}, "a\ufffdb"},
		{"invalid_utf8_to_replacement", []byte{'a', 0xff, 'b'}, "a\ufffdb"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := render.SafeBytes(tc.in)
			if got != tc.want {
				t.Fatalf("SafeBytes(%q) = %q, want %q",
					strings.ReplaceAll(string(tc.in), "\x00", `\0`), got, tc.want)
			}
		})
	}
}
