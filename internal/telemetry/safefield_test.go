package telemetry

import (
	"strings"
	"testing"
)

// TestSafeField_EscapesBackslash pins L7: a literal backslash is
// doubled so an attacker cannot forge an escape sequence. Input `\n`
// (backslash + n) must render as `\\n`, never as an escaped newline.
func TestSafeField_EscapesBackslash(t *testing.T) {
	if got := SafeField("k", `a\nb`); got != `a\\nb` {
		t.Fatalf("SafeField(%q) = %q, want %q", `a\nb`, got, `a\\nb`)
	}
	// A real newline still escapes to a single-backslash \n.
	if got := SafeField("k", "a\nb"); got != `a\nb` {
		t.Fatalf("newline: got %q", got)
	}
	// The output never contains a raw control byte.
	if strings.ContainsAny(SafeField("k", "x\\\n\ty"), "\n\r\t") {
		t.Fatal("output must never contain a raw control byte")
	}
}
