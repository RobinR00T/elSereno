package scanner_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
)

func TestProfileNamesFastestToGentlest(t *testing.T) {
	t.Parallel()
	got := scanner.ProfileNames()
	want := []string{"aggressive", "normal", "safe", "fragile"}
	if !slices.Equal(got, want) {
		t.Fatalf("ProfileNames() = %v, want %v", got, want)
	}
	if len(scanner.Profiles()) != len(want) {
		t.Fatalf("Profiles() has %d entries, want %d", len(scanner.Profiles()), len(want))
	}
}

func TestLookupProfile(t *testing.T) {
	t.Parallel()
	p, err := scanner.LookupProfile(" Safe ")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "safe" || p.MaxPerHost != 1 || p.MinHostInterval != time.Second {
		t.Fatalf("safe = %+v", p)
	}
	if _, err := scanner.LookupProfile("turbo"); !errors.Is(err, scanner.ErrUnknownProfile) {
		t.Fatalf("err = %v, want ErrUnknownProfile", err)
	}
}

// The default profile reproduces scan's pace before profiles existed.
func TestDefaultProfileKeepsPreviousPace(t *testing.T) {
	t.Parallel()
	p, err := scanner.LookupProfile(scanner.DefaultProfile)
	if err != nil {
		t.Fatal(err)
	}
	if p.MaxConcurrentTargets != 0 || p.MaxPerHost != 0 || p.MinHostInterval != 0 || p.RatePerSecond != 0 || p.MaxRetries != 2 {
		t.Fatalf("normal = %+v; want config caps, no pause, no rate, 2 retries", p)
	}
}

// Every profile gentler than normal keeps one probe per host and never
// retries more than normal.
func TestGentleProfilesAreGentle(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"safe", "fragile"} {
		p, _ := scanner.LookupProfile(name)
		if p.MaxPerHost != 1 || p.MinHostInterval <= 0 || p.RatePerSecond <= 0 || p.MaxRetries > 1 {
			t.Errorf("%s = %+v", name, p)
		}
	}
}

// Run honours MinHostInterval between probe starts on one address,
// across that address's ports.
func TestRunSpacesProbesOnOneHost(t *testing.T) {
	t.Parallel()
	const gap = 40 * time.Millisecond
	ts := []core.Target{target("10.0.0.9", 502), target("10.0.0.9", 102), target("10.0.0.9", 44818)}
	var (
		mu     sync.Mutex
		starts []time.Time
	)
	probe := func(context.Context, core.Target) (*core.Finding, error) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		return nil, nil
	}
	s := scanner.New(scanner.Options{MaxConcurrentTargets: 8, MaxConcurrentPerHost: 3, MinHostInterval: gap})
	findings, errs := s.Run(context.Background(), ts, probe)
	for range findings {
	}
	for range errs {
	}
	if len(starts) != 3 {
		t.Fatalf("%d probes, want 3", len(starts))
	}
	slices.SortFunc(starts, func(a, b time.Time) int { return a.Compare(b) })
	for i := 1; i < len(starts); i++ {
		if d := starts[i].Sub(starts[i-1]); d < gap-5*time.Millisecond {
			t.Fatalf("probes %d and %d started %v apart, want >= %v", i-1, i, d, gap)
		}
	}
}

// A shared Pacer carries the pace from one Run to the next (scan runs
// one per plugin).
func TestSharedPacerSpansRuns(t *testing.T) {
	t.Parallel()
	const gap = 40 * time.Millisecond
	pacer := scanner.NewHostPacer(1, gap)
	var (
		mu     sync.Mutex
		starts []time.Time
	)
	probe := func(context.Context, core.Target) (*core.Finding, error) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		return nil, nil
	}
	for i := 0; i < 2; i++ {
		s := scanner.New(scanner.Options{Pacer: pacer})
		f, e := s.Run(context.Background(), []core.Target{target("10.0.0.7", 502)}, probe)
		for range f {
		}
		for range e {
		}
	}
	if len(starts) != 2 {
		t.Fatalf("%d probes, want 2", len(starts))
	}
	if d := starts[1].Sub(starts[0]); d < gap-5*time.Millisecond {
		t.Fatalf("second run probed the host %v after the first, want >= %v", d, gap)
	}
}

// A probe that returns after the run was cancelled yields no finding:
// it was cut short, so what it saw is not an observation of the target.
func TestRunDropsFindingOfCancelledProbe(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	probe := func(context.Context, core.Target) (*core.Finding, error) {
		cancel()
		return &core.Finding{Protocol: "fake"}, nil
	}
	s := scanner.New(scanner.Options{MaxConcurrentTargets: 1})
	findings, errs := s.Run(ctx, []core.Target{target("10.0.0.5", 502)}, probe)
	n := 0
	for range findings {
		n++
	}
	for range errs {
	}
	if n != 0 {
		t.Fatalf("%d findings from a probe cut short by the cancel, want 0", n)
	}
}

// ProbeTimeout ends an attempt that hangs: no finding, a timeout error,
// and the attempt is retried.
func TestProbeTimeoutEndsHungAttempt(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		attempts int
	)
	probe := func(ctx context.Context, _ core.Target) (*core.Finding, error) {
		mu.Lock()
		attempts++
		mu.Unlock()
		<-ctx.Done() // a plugin whose connection was closed under it
		return &core.Finding{Protocol: "partial"}, nil
	}
	s := scanner.New(scanner.Options{MaxConcurrentTargets: 1, MaxRetries: 1, BaseBackoff: time.Millisecond, ProbeTimeout: 30 * time.Millisecond})
	start := time.Now()
	findings, errs := s.Run(context.Background(), []core.Target{target("10.0.0.6", 502)}, probe)
	n := 0
	for range findings {
		n++
	}
	var gotErr error
	for e := range errs {
		gotErr = e
	}
	if n != 0 {
		t.Fatalf("%d findings from attempts that ran out of time, want 0", n)
	}
	if !errors.Is(gotErr, core.ErrTimeout) {
		t.Fatalf("err = %v, want core.ErrTimeout", gotErr)
	}
	if attempts != 2 {
		t.Fatalf("%d attempts, want 2 (the timeout is retryable)", attempts)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("run took %v with a 30ms probe timeout", d)
	}
}
