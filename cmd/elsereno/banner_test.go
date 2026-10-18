package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"local/elsereno/internal/banner"
)

// TestRootHelp_NoBannerOffTerminal: help written to a buffer (a pipe,
// a script, this test) carries no logo, so tools that read the help
// see what they saw before the banner existed.
func TestRootHelp_NoBannerOffTerminal(t *testing.T) {
	for _, args := range [][]string{{}, {"--help"}, {"help"}} {
		root := newRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if strings.Contains(out.String(), "e l S e r e n o") {
			t.Fatalf("%v: banner printed off a terminal", args)
		}
		if !strings.Contains(out.String(), "Available Commands") {
			t.Fatalf("%v: help missing", args)
		}
	}
}

// TestWriteBanner: on a terminal the logo goes first; with --quiet or
// off a terminal nothing is written; colour follows banner.Show.
func TestWriteBanner(t *testing.T) {
	var b bytes.Buffer
	writeBanner(&b, banner.Env{TTY: true})
	if b.String() != banner.Plain()+"\n" {
		t.Fatal("terminal without 24-bit colour: want the plain logo")
	}
	b.Reset()
	writeBanner(&b, banner.Env{TTY: true, ColourTerm: "truecolor"})
	if !strings.Contains(b.String(), "\x1b[38;2;") {
		t.Fatal("truecolor terminal: want the colour logo")
	}
	b.Reset()
	writeBanner(&b, banner.Env{TTY: true, Quiet: true})
	writeBanner(&b, banner.Env{TTY: false})
	if b.Len() != 0 {
		t.Fatal("--quiet or no terminal: want nothing")
	}
}

// TestHelpOnTerminal: with a (faked) terminal the root help starts with
// the logo, and a subcommand's help, which goes through the same help
// func, does not carry it.
func TestHelpOnTerminal(t *testing.T) {
	saved := bannerEnvFor
	t.Cleanup(func() { bannerEnvFor = saved })
	bannerEnvFor = func(io.Writer) banner.Env { return banner.Env{TTY: true} }

	run := func(args ...string) string {
		root := newRootCmd()
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetArgs(args)
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return out.String()
	}
	for _, args := range [][]string{{}, {"--help"}, {"help"}} {
		if got := run(args...); !strings.HasPrefix(got, banner.Plain()+"\n") || !strings.Contains(got, "Available Commands") {
			t.Fatalf("%v: want the logo, then the help", args)
		}
	}
	if got := run("scan", "--help"); strings.Contains(got, "e l S e r e n o") || !strings.Contains(got, "--input") {
		t.Fatal("scan --help: want its help without the logo")
	}
}
