package main

import (
	"os"
	"syscall"
	"testing"
)

// A clean completion after the first signal exits 128+signum of that
// signal. Until 2026-10-21 it always returned 143, so a Ctrl-C (SIGINT)
// looked like a SIGTERM to the caller.
func TestSignalExitCode(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		sig  os.Signal
		want int
	}{{syscall.SIGINT, 130}, {syscall.SIGTERM, 143}} {
		first := make(chan os.Signal, 1)
		first <- c.sig
		if got := signalExitCode(first); got != c.want {
			t.Errorf("%v: exit %d, want %d", c.sig, got, c.want)
		}
	}
	if got := signalExitCode(make(chan os.Signal)); got != 143 {
		t.Errorf("no signal passed on: exit %d, want the 143 fallback", got)
	}
}
