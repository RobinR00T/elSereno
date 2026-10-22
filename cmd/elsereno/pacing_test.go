package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
)

// pacingCmd builds a command with the pacing flags and scan's global
// flags, parses args, and resolves the pace against cfg.
func pacingCmd(t *testing.T, cfg config.ScannerConfig, args ...string) (pacing, error) {
	t.Helper()
	var (
		pf                   pacingFlags
		rate, maxConc, retry int
	)
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().IntVar(&rate, "rate", 0, "")
	cmd.Flags().IntVar(&maxConc, "max-concurrent", 0, "")
	cmd.Flags().IntVar(&retry, "retries", 2, "")
	addPacingFlags(cmd, &pf)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return resolvePacing(cmd, pf, cfg, pacingOverrides{
		maxConcurrent: maxConc, maxConcurrentSet: cmd.Flags().Changed("max-concurrent"),
		ratePerSec: rate, rateSet: cmd.Flags().Changed("rate"),
		retries: retry, retriesSet: cmd.Flags().Changed("retries"),
	})
}

func TestResolvePacing(t *testing.T) {
	t.Parallel()
	cfg := config.ScannerConfig{MaxConcurrentTargets: 100, MaxConcurrentPerHost: 1}
	tests := []struct {
		name string
		cfg  config.ScannerConfig
		args []string
		want pacing
	}{
		{"default is normal with config caps", cfg, nil,
			pacing{profile: "normal", maxConcurrent: 100, maxPerHost: 1, retries: 2}},
		{"normal keeps a raised config per-host cap", config.ScannerConfig{MaxConcurrentTargets: 50, MaxConcurrentPerHost: 3}, nil,
			pacing{profile: "normal", maxConcurrent: 50, maxPerHost: 3, retries: 2}},
		{"safe profile", cfg, []string{"--profile", "safe"},
			pacing{profile: "safe", maxConcurrent: 16, maxPerHost: 1, interval: time.Second, ratePerSec: 10, retries: 1}},
		{"fragile profile", cfg, []string{"--profile=FRAGILE"},
			pacing{profile: "fragile", maxConcurrent: 4, maxPerHost: 1, interval: 10 * time.Second, ratePerSec: 2, retries: 0}},
		{"explicit flags beat the profile", cfg,
			[]string{"--profile", "safe", "--rate", "50", "--max-concurrent", "8", "--retries", "0", "--inter-probe-delay", "250ms", "--max-conns-per-host", "2"},
			pacing{profile: "safe", maxConcurrent: 8, maxPerHost: 2, interval: 250 * time.Millisecond, ratePerSec: 50, retries: 0}},
		{"explicit zero delay turns the pause off", cfg, []string{"--profile", "fragile", "--inter-probe-delay", "0s"},
			pacing{profile: "fragile", maxConcurrent: 4, maxPerHost: 1, ratePerSec: 2}},
		{"zero per-host flag keeps the profile's", cfg, []string{"--profile", "aggressive", "--max-conns-per-host", "0"},
			pacing{profile: "aggressive", maxConcurrent: 256, maxPerHost: 4, retries: 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := pacingCmd(t, tc.cfg, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestResolvePacingRejects(t *testing.T) {
	t.Parallel()
	cfg := config.ScannerConfig{MaxConcurrentTargets: 100, MaxConcurrentPerHost: 1}
	for _, args := range [][]string{
		{"--profile", "turbo"},
		{"--max-conns-per-host", "-1"},
		{"--inter-probe-delay", "-1s"},
	} {
		if _, err := pacingCmd(t, cfg, args...); err == nil {
			t.Errorf("%v: no error", args)
		} else if exitCode(err) != core.ExitUsage {
			t.Errorf("%v: exit %d, want 64 (%v)", args, exitCode(err), err)
		}
	}
}

func TestPacingString(t *testing.T) {
	t.Parallel()
	got := pacing{profile: "safe", maxConcurrent: 16, maxPerHost: 1, interval: time.Second, ratePerSec: 10, retries: 1}.String()
	want := "pacing safe: 16 in flight, 1 per host, 1s between probes to a host, 10 probes/s overall, 1 retry"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	if s := (pacing{profile: "normal", maxConcurrent: 100, maxPerHost: 1, retries: 2}).String(); !strings.Contains(s, "no pause") || !strings.Contains(s, "no overall rate cap") {
		t.Fatalf("normal line %q", s)
	}
}

// The profiles help lists every profile and says the numbers are not
// vendor-validated.
func TestProfilesHelp(t *testing.T) {
	t.Parallel()
	h := profilesHelp()
	for _, n := range scanner.ProfileNames() {
		if !strings.Contains(h, "  "+n) {
			t.Errorf("help lacks %s:\n%s", n, h)
		}
	}
	if !strings.Contains(h, "not values validated") {
		t.Errorf("help lacks the caveat:\n%s", h)
	}
}

// Before 2026-10-21 discover dialled every port of a host at once. With
// a per-host pacer the connects to one host are spaced, whatever
// --parallel is.
func TestSweepPacedSpacesConnectsToOneHost(t *testing.T) {
	const gap = 40 * time.Millisecond
	var (
		mu      sync.Mutex
		accepts []time.Time
	)
	ports := make([]pluginPort, 0, 3)
	for i := 0; i < 3; i++ {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				mu.Lock()
				accepts = append(accepts, time.Now())
				mu.Unlock()
				_ = c.Close()
			}
		}()
		ap := netip.MustParseAddrPort(ln.Addr().String())
		ports = append(ports, pluginPort{Port: int(ap.Port()), PluginID: "p"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hits := sweepPaced(ctx, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ports, time.Second,
		sweepPace{parallel: 64, pacer: scanner.NewHostPacer(1, gap)})
	if len(hits) != 3 {
		t.Fatalf("%d hits, want 3", len(hits))
	}
	// Accepts can trail the dial slightly; wait for the last one.
	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		n := len(accepts)
		mu.Unlock()
		if n == 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	slices.SortFunc(accepts, func(a, b time.Time) int { return a.Compare(b) })
	for i := 1; i < len(accepts); i++ {
		if d := accepts[i].Sub(accepts[i-1]); d < gap-10*time.Millisecond {
			t.Fatalf("connects %d and %d to one host %v apart, want >= %v", i-1, i, d, gap)
		}
	}
}

// timedProtocol records when each probe starts.
type timedProtocol struct {
	mu     *sync.Mutex
	starts *[]time.Time
}

func (timedProtocol) Metadata() core.PluginMetadata { return core.PluginMetadata{Name: "timed"} }
func (p timedProtocol) Probe(context.Context, core.Target) (*core.Finding, error) {
	p.mu.Lock()
	*p.starts = append(*p.starts, time.Now())
	p.mu.Unlock()
	return nil, nil
}
func (timedProtocol) REPL(context.Context, *core.Session) error { return nil }
func (timedProtocol) ProxyHandler() core.ProxyHandler           { return nil }

// scan runs plugins one after another; the inter-probe delay holds
// across them, so the second plugin does not hit the host right after
// the first one.
func TestRunPlansKeepsPaceAcrossPlugins(t *testing.T) {
	t.Parallel()
	const gap = 50 * time.Millisecond
	var (
		mu     sync.Mutex
		starts []time.Time
	)
	mk := func(name string) core.Plugin {
		return core.Plugin{PluginMetadata: core.PluginMetadata{Name: name},
			Factory: func() core.Protocol { return timedProtocol{mu: &mu, starts: &starts} }}
	}
	tgt := []core.Target{{Address: netip.MustParseAddr("192.0.2.10"), Port: 502}}
	runs := []pluginRun{{plugin: mk("a"), targets: tgt}, {plugin: mk("b"), targets: tgt}}
	opts := scanOpts{pace: pacing{profile: "safe", maxConcurrent: 4, maxPerHost: 1, interval: gap}}
	cfg := config.Config{Scanner: config.ScannerConfig{MaxConcurrentTargets: 4, MaxConcurrentPerHost: 1}}
	if _, err := runPlans(context.Background(), cfg, opts, runs, func(core.Finding, core.Target) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	if len(starts) != 2 {
		t.Fatalf("%d probes, want 2", len(starts))
	}
	if d := starts[1].Sub(starts[0]); d < gap-5*time.Millisecond {
		t.Fatalf("second plugin probed the host %v after the first, want >= %v", d, gap)
	}
}

// The sweep walks port by port across hosts, so with one connect per
// host the workers spread over hosts instead of queueing on the first
// host's ports. The loopback ports are closed; only the pacing order
// matters, not whether anything answers.
func TestSweepPacedSpreadsAcrossHosts(t *testing.T) {
	t.Parallel()
	const gap = 100 * time.Millisecond
	hosts := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")}
	ports := []pluginPort{}
	for p := 1; p <= 6; p++ {
		ports = append(ports, pluginPort{Port: p, PluginID: "p"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	_ = sweepPaced(ctx, hosts, ports, 50*time.Millisecond, sweepPace{parallel: 3, pacer: scanner.NewHostPacer(1, gap)})
	el := time.Since(start)
	t.Logf("sweep of 3 hosts x 6 ports took %v", el)
	// Port-major: six rounds of three hosts in parallel, five gaps
	// (~500ms). Host-major with three workers queues behind one host at
	// a time, so most rounds use one worker (well over 1s).
	if el > 900*time.Millisecond {
		t.Fatalf("sweep took %v; the workers queued on one host", el)
	}
}

// A port two plugins claim is dialled once, and the hit lists both.
func TestSweepDialsSharedPortOnce(t *testing.T) {
	t.Parallel()
	var accepts atomic.Int32
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	port := int(ap.Port())
	ports := []pluginPort{{Port: port, PluginID: "melsoft"}, {Port: port, PluginID: "slmp"}}
	hits := sweep(context.Background(), []netip.Addr{ap.Addr()}, ports, 4, time.Second)
	if len(hits) != 1 || !slices.Equal(hits[0].ProtocolHints, []string{"melsoft", "slmp"}) {
		t.Fatalf("hits = %+v, want one hit with both plugins", hits)
	}
	time.Sleep(50 * time.Millisecond)
	if n := accepts.Load(); n != 1 {
		t.Fatalf("%d connects to the shared port, want 1", n)
	}
}
