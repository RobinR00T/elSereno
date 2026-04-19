package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
)

func target(addr string, port int) core.Target {
	a, _ := netip.ParseAddr(addr)
	p, _ := core.NewPort(port)
	return core.Target{Address: a, Port: p}
}

func TestRunHappyPath(t *testing.T) {
	t.Parallel()
	ts := []core.Target{target("10.0.0.1", 502), target("10.0.0.2", 502)}
	s := scanner.New(scanner.Options{MaxConcurrentTargets: 8})
	probe := func(_ context.Context, tt core.Target) (*core.Finding, error) {
		return &core.Finding{ID: core.UUID(tt.Address.String()), Protocol: "modbus"}, nil
	}
	findings, errs := s.Run(context.Background(), ts, probe)
	seen := map[string]struct{}{}
	for f := range findings {
		seen[string(f.ID)] = struct{}{}
	}
	for range errs {
		t.Fatal("unexpected error")
	}
	if len(seen) != 2 {
		t.Fatalf("got %d findings, want 2", len(seen))
	}
}

func TestRunErrorsReported(t *testing.T) {
	t.Parallel()
	ts := []core.Target{target("10.0.0.1", 502)}
	s := scanner.New(scanner.Options{})
	probe := func(_ context.Context, _ core.Target) (*core.Finding, error) {
		return nil, fmt.Errorf("boom")
	}
	findings, errs := s.Run(context.Background(), ts, probe)
	for range findings {
	}
	var got error
	for e := range errs {
		got = e
	}
	if got == nil {
		t.Fatal("expected error")
	}
}

func TestRunNoTargets(t *testing.T) {
	t.Parallel()
	s := scanner.New(scanner.Options{})
	_, errs := s.Run(context.Background(), nil, func(context.Context, core.Target) (*core.Finding, error) { return nil, nil })
	err := <-errs
	if !errors.Is(err, scanner.ErrNoTargets) {
		t.Fatalf("got %v, want ErrNoTargets", err)
	}
}

func TestRunRetries(t *testing.T) {
	t.Parallel()
	ts := []core.Target{target("10.0.0.1", 502)}
	s := scanner.New(scanner.Options{
		MaxRetries:     2,
		BaseBackoff:    1 * time.Millisecond,
		JitterFraction: 0.0,
	})
	var calls atomic.Int32
	probe := func(_ context.Context, _ core.Target) (*core.Finding, error) {
		calls.Add(1)
		return nil, core.ErrTimeout
	}
	findings, errs := s.Run(context.Background(), ts, probe)
	for range findings {
	}
	for range errs {
	}
	// 1 initial attempt + 2 retries = 3 calls.
	if n := calls.Load(); n != 3 {
		t.Fatalf("calls = %d, want 3", n)
	}
}

func TestDedupe(t *testing.T) {
	t.Parallel()
	ts := []core.Target{
		target("10.0.0.1", 502),
		target("10.0.0.1", 502), // duplicate
		target("10.0.0.1", 102),
	}
	got := scanner.Dedupe(ts)
	if len(got) != 2 {
		t.Fatalf("Dedupe len = %d, want 2", len(got))
	}
}
