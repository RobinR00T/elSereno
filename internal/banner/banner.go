// Package banner holds the elSereno ASCII logo (a skeleton night
// watchman with his lantern) that `elsereno` prints above its help on
// an interactive terminal.
//
// Two embedded copies: plain ASCII, and the same art with 24-bit ANSI
// colours (ivory skeleton, blue cloak, amber lantern). Stripped of its
// escape sequences the colour copy is byte-identical to the plain one;
// a test holds that.
package banner

import (
	_ "embed"
	"io"
)

//go:embed banner.txt
var plain string

//go:embed banner_ansi.txt
var ansi string

// Plain returns the logo as plain ASCII, newline-terminated.
func Plain() string { return plain }

// Env is what Show reads from the process: whether the writer is a
// terminal, the --quiet flag and three environment variables.
type Env struct {
	TTY        bool   // the writer is a terminal
	Quiet      bool   // --quiet
	NoColour   string //nolint:misspell // NO_COLOR, no-color.org: any value turns colour off
	Term       string // TERM: "dumb" turns colour off
	ColourTerm string //nolint:misspell // COLORTERM: colour only with "truecolor" or "24bit"
}

// Show reports whether to print the logo and whether in colour. Never
// off a terminal (a pipe, a file, a script reading help) and never with
// --quiet. Colour needs a terminal that declares 24-bit support, since
// the art uses 38;2 sequences; anything else gets the plain copy.
func Show(e Env) (show, colour bool) {
	if !e.TTY || e.Quiet {
		return false, false
	}
	colour = e.NoColour == "" && e.Term != "dumb" &&
		(e.ColourTerm == "truecolor" || e.ColourTerm == "24bit") //nolint:misspell // COLORTERM's own value
	return true, colour
}

// Write prints the logo and a blank line to w, in colour or plain.
func Write(w io.Writer, colour bool) error {
	art := plain
	if colour {
		art = ansi
	}
	_, err := io.WriteString(w, art+"\n")
	return err
}
