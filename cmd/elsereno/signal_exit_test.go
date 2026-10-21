package main

import (
	"sync/atomic"
	"syscall"
	"testing"
)

// A clean completion after the first signal exits 128+signum of that
// signal. Until 2026-10-21 it always returned 143, so a Ctrl-C (SIGINT)
// looked like a SIGTERM to the caller.
func TestSignalExitCode(t *testing.T) {
	t.Parallel()
	var intr, term, none atomic.Value
	intr.Store(syscall.SIGINT)
	term.Store(syscall.SIGTERM)
	if got := signalExitCode(&intr); got != 130 {
		t.Errorf("SIGINT: exit %d, want 130", got)
	}
	if got := signalExitCode(&term); got != 143 {
		t.Errorf("SIGTERM: exit %d, want 143", got)
	}
	if got := signalExitCode(&none); got != 143 {
		t.Errorf("no signal stored: exit %d, want the 143 fallback", got)
	}
}
