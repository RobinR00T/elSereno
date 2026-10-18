package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"local/elsereno/internal/banner"
)

// installBanner prints the elSereno logo above the root help: bare
// `elsereno`, `elsereno --help` and `elsereno help`. Subcommand help is
// untouched, and nothing is printed off a terminal or with --quiet, so
// scripts and pipes that read the help get exactly what they got before.
func installBanner(root *cobra.Command) *cobra.Command {
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if !c.HasParent() {
			writeBanner(c.OutOrStdout(), bannerEnvFor(c.OutOrStdout()))
		}
		defaultHelp(c, args)
	})
	return root
}

// bannerEnvFor is bannerEnv; tests swap it to fake a terminal.
var bannerEnvFor = bannerEnv

// bannerEnv reads the terminal state of w, --quiet and the colour
// variables for banner.Show.
func bannerEnv(w io.Writer) banner.Env {
	tty := false
	if f, ok := w.(*os.File); ok {
		tty = term.IsTerminal(int(f.Fd())) // #nosec G115 -- a file descriptor fits in int
	}
	return banner.Env{
		TTY:        tty,
		Quiet:      flagQuiet,
		NoColour:   os.Getenv("NO_COLOR"), //nolint:misspell // env var name
		Term:       os.Getenv("TERM"),
		ColourTerm: os.Getenv("COLORTERM"), //nolint:misspell // env var name
	}
}

func writeBanner(w io.Writer, e banner.Env) {
	if show, colour := banner.Show(e); show {
		_ = banner.Write(w, colour)
	}
}
