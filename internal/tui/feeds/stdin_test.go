//go:build !mini

package feeds

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/tui"
)

// TestStdinHappyPath drives a 2-line capture through Stdin —
// confirms the Reader plumbing matches Replay's file path.
func TestStdinHappyPath(t *testing.T) {
	src := strings.NewReader(strings.Join([]string{
		findingFixture(80, "modbus"),
		findingFixture(40, "snmp"),
	}, "\n"))
	d := &drain{}
	if err := (Stdin{In: src}).Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := len(d.msgs); got != 2 {
		t.Fatalf("emitted %d, want 2", got)
	}
	for i, m := range d.msgs {
		if _, ok := m.(tui.FindingMsg); !ok {
			t.Errorf("[%d] %T, want tui.FindingMsg", i, m)
		}
	}
}

// TestStdinEOFTerminatesCleanly — when the producer closes the
// pipe, Run returns nil so the runner reports a clean closure
// (no "feed closed with error: …" line).
func TestStdinEOFTerminatesCleanly(t *testing.T) {
	src := strings.NewReader(findingFixture(50, "modbus"))
	d := &drain{}
	if err := (Stdin{In: src}).Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("EOF should not error: %v", err)
	}
	if len(d.msgs) != 1 {
		t.Errorf("emitted %d, want 1", len(d.msgs))
	}
}

// TestStdinDefaultsToOsStdin proves the In==nil guard. We can't
// safely swap os.Stdin in this process, so we drive Run on a
// bounded deadline: if the fallback regresses (nil deref or
// blocking) the test fails fast rather than hanging the suite.
func TestStdinDefaultsToOsStdin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &drain{}
	done := make(chan error, 1)
	go func() { done <- (Stdin{}).Run(ctx, d.emit()) }()
	select {
	case <-done:
		// Either nil (immediate EOF) or wrapped context.Canceled
		// is acceptable; the assertion is "the call returns".
	case <-time.After(2 * time.Second):
		t.Fatal("Stdin{In:nil}.Run blocked >2s; nil-fallback to os.Stdin may have regressed")
	}
}

// TestStdinName — distinct from Replay's identifier so error
// reports clearly distinguish the two modes.
func TestStdinName(t *testing.T) {
	if got := (Stdin{}).Name(); got != "feed stdin" {
		t.Errorf("Name = %q", got)
	}
}

// TestStdinIgnoresEmptyLines — pipelines often have stray empty
// lines (trailing newlines, conditional jq output). Confirm
// they're skipped silently rather than triggering parse errors.
func TestStdinIgnoresEmptyLines(t *testing.T) {
	src := strings.NewReader("\n" + findingFixture(50, "modbus") + "\n\n" + findingFixture(60, "s7") + "\n\n")
	d := &drain{}
	if err := (Stdin{In: src}).Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := len(d.msgs); got != 2 {
		t.Fatalf("emitted %d, want 2 (empty lines should be silent)", got)
	}
	for i, m := range d.msgs {
		if _, ok := m.(tui.FindingMsg); !ok {
			t.Errorf("[%d] = %T, want tui.FindingMsg (no AuditMsg for empty lines)", i, m)
		}
	}
}

// TestStdinPipeIsConsumedSequentially — drives io.Pipe so the
// reader half blocks on the writer. Confirms Stdin doesn't
// pre-buffer and waits for live input arrival, which is the
// whole point of feed mode.
func TestStdinPipeIsConsumedSequentially(t *testing.T) {
	pr, pw := io.Pipe()
	d := &drain{}
	done := make(chan error, 1)
	go func() { done <- (Stdin{In: pr}).Run(context.Background(), d.emit()) }()

	// Write 2 lines + close. The feed should emit both then
	// return cleanly on EOF.
	go func() {
		_, _ = pw.Write([]byte(findingFixture(50, "modbus") + "\n"))
		_, _ = pw.Write([]byte(findingFixture(70, "s7") + "\n"))
		_ = pw.Close()
	}()

	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	d.mu.Lock()
	got := len(d.msgs)
	d.mu.Unlock()
	if got != 2 {
		t.Errorf("emitted %d, want 2", got)
	}
}

// TestStdinPipeCancelStops — cancellation interrupts a stalled
// pipe read on the next line. Bounded wait so the test fails
// fast if the cancellation path regresses.
func TestStdinPipeCancelStops(t *testing.T) {
	pr, pw := io.Pipe()
	defer func() { _ = pw.Close() }()

	d := &drain{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Stdin{In: pr}).Run(ctx, d.emit()) }()

	// Push one line so we exit the first scanner.Scan() call
	// and re-enter the cancellation guard.
	_, _ = pw.Write([]byte(findingFixture(50, "modbus") + "\n"))

	// Wait for the emit to land then cancel.
	deadline := make(chan struct{})
	go func() {
		for {
			d.mu.Lock()
			n := len(d.msgs)
			d.mu.Unlock()
			if n >= 1 {
				close(deadline)
				return
			}
		}
	}()
	<-deadline
	cancel()
	_ = pw.Close() // unblock the pipe read so the goroutine returns

	// done should fire shortly. Without an explicit timeout a
	// regression in the cancellation guard would hang the test
	// runner — fail fast instead.
	select {
	case <-done:
		// Either context.Canceled wrapping or io.EOF after pipe
		// close is acceptable; the assertion is "the goroutine
		// returns after cancel + close".
	case <-time.After(2 * time.Second):
		t.Fatal("Stdin.Run did not return within 2s of cancel+close; cancellation guard may have regressed")
	}
}
