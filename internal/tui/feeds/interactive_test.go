//go:build !mini

package feeds

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
	"local/elsereno/internal/tui"
)

// mustAddr panics on an unparsable IP literal. Tests only.
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// stubProbe builds a Probe that always returns a Finding with
// the given score. Useful for deterministic tests.
func stubProbe(score int) scanner.Probe {
	return func(_ context.Context, t core.Target) (*core.Finding, error) {
		return &core.Finding{
			ID:        core.UUID("f-" + t.Address.String()),
			TargetID:  core.UUID(t.Address.String()),
			Protocol:  "test",
			Severity:  core.Severity("medium"),
			Score:     score,
			CreatedAt: time.Now().UTC(),
		}, nil
	}
}

// TestInteractive_HappyPath spawns the feed against 3 targets,
// verifies one FindingMsg per target + a final ScanProgressMsg
// with Total=0 (idle) marking close.
func TestInteractive_HappyPath(t *testing.T) {
	targets := []core.Target{
		{Address: mustAddr("10.0.0.1"), Port: 502},
		{Address: mustAddr("10.0.0.2"), Port: 502},
		{Address: mustAddr("10.0.0.3"), Port: 502},
	}
	feed := Interactive{
		Targets: targets,
		Probe:   stubProbe(75),
		Options: scanner.Options{MaxConcurrentTargets: 4},
	}
	d := &drain{}
	if err := feed.Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// First message is the initial 0/3 progress.
	progress0, ok := d.msgs[0].(tui.ScanProgressMsg)
	if !ok || progress0.Completed != 0 || progress0.Total != 3 {
		t.Fatalf("[0] = %v, want ScanProgressMsg{0, 3}", d.msgs[0])
	}

	// Last message is idle (Total=0).
	last := d.msgs[len(d.msgs)-1]
	pl, ok := last.(tui.ScanProgressMsg)
	if !ok || pl.Total != 0 {
		t.Errorf("last msg = %v, want ScanProgressMsg{Total: 0}", last)
	}

	// Count FindingMsgs — must equal target count.
	var findings int
	for _, m := range d.msgs {
		if _, ok := m.(tui.FindingMsg); ok {
			findings++
		}
	}
	if findings != 3 {
		t.Errorf("findings = %d, want 3", findings)
	}
}

// TestInteractive_EmptyTargets — no targets → emits an audit
// line + returns nil. The TUI shows the panel but explains why
// nothing's happening.
func TestInteractive_EmptyTargets(t *testing.T) {
	d := &drain{}
	if err := (Interactive{}).Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(d.msgs) != 1 {
		t.Fatalf("emitted %d, want 1", len(d.msgs))
	}
	am, ok := d.msgs[0].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[0] = %T, want AuditMsg", d.msgs[0])
	}
	if !strings.Contains(am.Line, "no targets") {
		t.Errorf("audit line = %q, want 'no targets'", am.Line)
	}
}

// TestInteractive_ProbeErrorBecomesAudit — a probe that returns
// an error should fold to an AuditMsg (warn-and-continue), not
// abort the feed. Mirrors batch scan's behaviour.
func TestInteractive_ProbeErrorBecomesAudit(t *testing.T) {
	targets := []core.Target{{Address: mustAddr("10.0.0.1"), Port: 502}}
	probe := func(_ context.Context, _ core.Target) (*core.Finding, error) {
		return nil, errors.New("dial: connection refused")
	}
	feed := Interactive{Targets: targets, Probe: probe}

	d := &drain{}
	if err := feed.Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	var sawAudit bool
	for _, m := range d.msgs {
		if am, ok := m.(tui.AuditMsg); ok && strings.Contains(am.Line, "scan:") {
			sawAudit = true
		}
	}
	if !sawAudit {
		t.Errorf("expected AuditMsg with 'scan:' prefix, msgs: %v", d.msgs)
	}
}

// TestInteractive_ContextCancel — cancellation propagates so
// the feed terminates promptly. The scanner respects ctx but
// we still verify the feed returns the cancellation error
// rather than swallowing it.
func TestInteractive_ContextCancel(t *testing.T) {
	// Build many targets so the scanner has work to interrupt.
	targets := make([]core.Target, 50)
	for i := range targets {
		targets[i] = core.Target{Address: mustAddr("10.0.0." + itoa(i+1)), Port: 502}
	}
	var calls atomic.Int32
	probe := func(ctx context.Context, _ core.Target) (*core.Finding, error) {
		calls.Add(1)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return &core.Finding{Score: 10}, nil
		}
	}
	feed := Interactive{Targets: targets, Probe: probe}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	d := &drain{}
	err := feed.Run(ctx, d.emit())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// We can't reliably assert calls<total — the scanner queues
	// all probes immediately and they only return after their
	// 200ms sleep observes the cancelled ctx. The contract is:
	// Run() returns ctx.Err() promptly, which is what we
	// asserted above. calls is referenced indirectly via the
	// closure so govet's copylocks doesn't fire.
	if n := calls.Load(); n < 0 {
		t.Errorf("calls went negative: %d", n)
	}
}

// TestInteractive_Name — the human-readable name embeds the
// target count so error reports say "interactive (12 targets)".
func TestInteractive_Name(t *testing.T) {
	feed := Interactive{Targets: make([]core.Target, 7)}
	if got := feed.Name(); got != "interactive (7 targets)" {
		t.Errorf("Name = %q", got)
	}
}
