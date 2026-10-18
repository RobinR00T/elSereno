package banner

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

var sgr = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestAnsiStrippedEqualsPlain: the colour copy is the plain art plus
// escape sequences, nothing else, so the two can never drift apart.
func TestAnsiStrippedEqualsPlain(t *testing.T) {
	if got := sgr.ReplaceAllString(ansi, ""); got != plain {
		t.Fatal("banner_ansi.txt stripped of SGR sequences differs from banner.txt")
	}
}

// TestArtIsPlainASCIIAndNarrow: printable ASCII only (no control bytes
// besides the newline) and at most 40 columns, so it fits an 80-column
// terminal with room to spare.
func TestArtIsPlainASCIIAndNarrow(t *testing.T) {
	for i, line := range strings.Split(strings.TrimSuffix(plain, "\n"), "\n") {
		if len(line) > 40 {
			t.Errorf("line %d is %d columns wide", i+1, len(line))
		}
		for _, c := range []byte(line) {
			if c < 0x20 || c > 0x7e {
				t.Fatalf("line %d has byte 0x%02x", i+1, c)
			}
		}
	}
	if !strings.Contains(plain, "e l S e r e n o") {
		t.Fatal("the name line is missing")
	}
}

// TestAnsiUsesOnlyKnownSequences: the three palette colours and the
// reset, so the embedded file cannot smuggle other terminal escapes.
func TestAnsiUsesOnlyKnownSequences(t *testing.T) {
	allowed := map[string]bool{
		"\x1b[0m":                true,
		"\x1b[38;2;115;151;189m": true, // cloak blue
		"\x1b[38;2;241;228;199m": true, // skeleton ivory
		"\x1b[38;2;255;184;77m":  true, // lantern amber
	}
	for _, s := range sgr.FindAllString(ansi, -1) {
		if !allowed[s] {
			t.Fatalf("unexpected sequence %q", s)
		}
	}
	if strings.Count(ansi, "\x1b") != len(sgr.FindAllString(ansi, -1)) {
		t.Fatal("an escape byte outside an SGR sequence")
	}
}

func TestShow(t *testing.T) {
	cases := []struct {
		name         string
		env          Env
		show, colour bool
	}{
		{"pipe", Env{TTY: false, ColourTerm: "truecolor"}, false, false},
		{"quiet", Env{TTY: true, Quiet: true, ColourTerm: "truecolor"}, false, false},
		{"truecolor", Env{TTY: true, ColourTerm: "truecolor"}, true, true},
		{"24bit", Env{TTY: true, ColourTerm: "24bit"}, true, true},
		{"no COLORTERM", Env{TTY: true}, true, false},
		{"NO_COLOR", Env{TTY: true, NoColour: "1", ColourTerm: "truecolor"}, true, false}, //nolint:misspell // env var name
		{"dumb", Env{TTY: true, Term: "dumb", ColourTerm: "truecolor"}, true, false},
	}
	for _, c := range cases {
		show, colour := Show(c.env)
		if show != c.show || colour != c.colour {
			t.Errorf("%s: Show = (%v, %v), want (%v, %v)", c.name, show, colour, c.show, c.colour)
		}
	}
}

func TestWrite(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, false); err != nil {
		t.Fatal(err)
	}
	if b.String() != plain+"\n" || strings.Contains(b.String(), "\x1b") {
		t.Fatal("plain Write is not the plain art plus a blank line")
	}
	b.Reset()
	if err := Write(&b, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "\x1b[38;2;255;184;77m") || !strings.HasSuffix(b.String(), "\x1b[0m\n\n") {
		t.Fatal("colour Write lacks the lantern colour or the final reset")
	}
}
