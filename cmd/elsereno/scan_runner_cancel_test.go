//go:build !mini

package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/core"
	"local/elsereno/internal/repo"
	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/stream"
)

// slowTargets starts n loopback listeners that accept and hold each
// connection for hold without sending anything, all counted on one
// counter, and writes them to a list file.
func slowTargets(t *testing.T, n int, hold time.Duration) (string, *atomic.Int32) {
	t.Helper()
	var accepted atomic.Int32
	var lines []string
	for i := 0; i < n; i++ {
		ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted.Add(1)
				go func() {
					time.Sleep(hold)
					_ = c.Close()
				}()
			}
		}()
		lines = append(lines, ln.Addr().String())
	}
	return writeList(t, lines), &accepted
}

func writeList(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestScanRunner_CancelStopsTraffic: cancelling a running dashboard
// scan stops its probes (no connection after the cancel) and closes
// its run as cancelled. Until 2026-10-17 the probes went on and the run
// was recorded as completed (PITF-094).
func TestScanRunner_CancelStopsTraffic(t *testing.T) {
	list, accepted := slowTargets(t, 4, 3*time.Second)
	store := scanorch.NewMemoryStore()
	rec := &fakeRecorder{}
	w := &scanorch.Worker{
		Store:      store,
		Runner:     &defaultScanRunner{concurrency: 1, recorder: rec},
		CancelPoll: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	job, err := store.Submit(ctx, scanorch.SubmitRequest{Input: "list:" + list, Plugins: []string{"banner"}}, "op")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan scanorch.Job, 1)
	go func() {
		j, _ := w.Process(ctx, job.ID)
		done <- j
	}()
	for accepted.Load() == 0 {
		select {
		case <-ctx.Done():
			t.Fatal("the first probe never connected")
		case <-time.After(10 * time.Millisecond):
		}
	}
	atCancel := accepted.Load()
	if _, err := store.Transition(ctx, job.ID, scanorch.StateCancelled, scanorch.TransitionFields{}); err != nil {
		t.Fatal(err)
	}
	var final scanorch.Job
	select {
	case final = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the job kept running after the cancel")
	}
	time.Sleep(300 * time.Millisecond)
	if got := accepted.Load(); got > atCancel {
		t.Errorf("%d connections after the cancel (%d before it)", got-atCancel, atCancel)
	}
	if final.State != scanorch.StateCancelled {
		t.Errorf("job ended %s, want cancelled", final.State)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.status != "cancelled" {
		t.Errorf("run closed as %q, want cancelled", rec.status)
	}
}

// TestScanRunner_NoTrafficWhenRunCannotOpen: if the run cannot be
// recorded, the job fails before any probe.
func TestScanRunner_NoTrafficWhenRunCannotOpen(t *testing.T) {
	addr, accepted, stop := countingListener(t)
	defer stop()
	rec := &fakeRecorder{startErr: errors.New("database down")}
	r := &defaultScanRunner{recorder: rec}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, err := r.Run(ctx, scanorch.Job{ID: "j", Input: "list:" + writeList(t, []string{addr}), Plugins: []string{"banner"}}, nil); err == nil {
		t.Fatal("Run succeeded although the run could not be opened")
	}
	stop()
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections although the run could not be opened", n)
	}
}

// TestScanRunner_WriteFailureStopsRemainingProbes: after the first
// finding that cannot be kept, no further target and no further plugin
// is probed.
func TestScanRunner_WriteFailureStopsRemainingProbes(t *testing.T) {
	var addrs []string
	var counters []*atomic.Int32
	for i := 0; i < 3; i++ {
		addr, n, stop := countingListener(t)
		defer stop()
		addrs, counters = append(addrs, addr), append(counters, n)
	}
	rec := &fakeRecorder{recordErr: errors.New("disk full")}
	r := &defaultScanRunner{concurrency: 1, recorder: rec}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	job := scanorch.Job{ID: "j", Input: "list:" + writeList(t, addrs), Plugins: []string{"banner", "codesys-active"}}
	if _, _, err := r.Run(ctx, job, nil); err == nil {
		t.Fatal("Run succeeded although no finding could be kept")
	}
	total := int32(0)
	for _, n := range counters {
		total += n.Load()
	}
	// banner's first probe (and at most one already in flight), and
	// nothing from codesys-active.
	if total > 2 {
		t.Fatalf("%d connections after the first failed write, want at most 2", total)
	}
}

// ctxQuerier records whether each statement ran with a live context.
type ctxQuerier struct {
	execs, rows, deadCtx int
}

func (q *ctxQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not used")
}

func (q *ctxQuerier) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	q.rows++
	if ctx.Err() != nil {
		q.deadCtx++
	}
	return idRow{}
}

// idRow answers a target upsert with a fixed id.
type idRow struct{}

func (idRow) Scan(dest ...any) error {
	id, ok := dest[0].(*string)
	if !ok {
		return errors.New("idRow: unexpected destination")
	}
	*id = "22222222-2222-4222-8222-222222222222"
	return nil
}
func (q *ctxQuerier) Exec(ctx context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	q.execs++
	if ctx.Err() != nil {
		q.deadCtx++
	}
	return pgconn.CommandTag{}, nil
}

// TestDBRunRecorder_FinishOutlivesCancel: a cancelled job's run is
// still closed, with a context of its own.
func TestDBRunRecorder_FinishOutlivesCancel(t *testing.T) {
	q := &ctxQuerier{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dbRunRecorder{w: repo.NewRunWriter(q)}.Finish(ctx, "run-1", "cancelled", nil)
	if q.execs != 1 || q.deadCtx != 0 {
		t.Fatalf("FinishRun ran %d times, %d with a cancelled context; want 1, 0", q.execs, q.deadCtx)
	}
}

// TestServeWiring_QueuedJobRuns: serve's scan orchestrator runs a job
// queued in its store. Until 2026-10-17 nothing fed the worker pool and
// every job stayed queued (PITF-094).
func TestServeWiring_QueuedJobRuns(t *testing.T) {
	addr, accepted, stop := countingListener(t)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, pool, err := buildScanOrchestrator(ctx, serveOpts{scanStore: "memory", scanPool: 1}, nil, stream.New(16))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Stop()
	job, err := store.Submit(ctx, scanorch.SubmitRequest{Input: "list:" + writeList(t, []string{addr}), Plugins: []string{"banner"}}, "op")
	if err != nil {
		t.Fatal(err)
	}
	for {
		j, err := store.Get(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if j.State == scanorch.StateCompleted {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("job still %s; serve's pool never ran it", j.State)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if accepted.Load() == 0 {
		t.Fatal("the job completed without connecting to its target")
	}
}

// TestAnnounceEnabledSchedules: serve says how many schedules will
// fire, in the singular for one, and nothing with none.
func TestAnnounceEnabledSchedules(t *testing.T) {
	ctx := context.Background()
	store := scanorch.NewMemoryScheduleStore()
	var out bytes.Buffer
	announceEnabledSchedules(ctx, &out, store)
	if out.Len() != 0 {
		t.Fatalf("no schedules, yet: %q", out.String())
	}
	for i, disabled := range []bool{false, true} {
		if _, err := store.Create(ctx, scanorch.CreateScheduleRequest{
			Name:            "s" + string(rune('a'+i)),
			Template:        scanorch.SubmitRequest{Input: "list:-"},
			IntervalSeconds: 3600,
			StartDisabled:   disabled,
		}, "op"); err != nil {
			t.Fatal(err)
		}
	}
	announceEnabledSchedules(ctx, &out, store)
	if !strings.Contains(out.String(), "1 enabled schedule runs a real scan") {
		t.Fatalf("announce = %q", out.String())
	}
}

// TestSafeProbe_PanicBecomesError: a probe that panics on hostile bytes
// fails that probe instead of taking serve down.
func TestSafeProbe_PanicBecomesError(t *testing.T) {
	probe := safeProbe("boom", func(context.Context, core.Target) (*core.Finding, error) {
		panic("probe panic")
	}, nil)
	f, err := probe(context.Background(), core.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: 502})
	if f != nil || err == nil || !strings.Contains(err.Error(), "boom probe panicked on 127.0.0.1:502") {
		t.Fatalf("got %v, %v", f, err)
	}
}

// TestScanRunner_NoRunWithoutMatchingPlugin: a job whose plugins match
// no target port opens no run (no empty error runs).
func TestScanRunner_NoRunWithoutMatchingPlugin(t *testing.T) {
	addr, accepted, stop := countingListener(t)
	defer stop()
	rec := &fakeRecorder{}
	r := &defaultScanRunner{recorder: rec}
	_, _, err := r.Run(context.Background(), scanorch.Job{ID: "j", Input: "list:" + writeList(t, []string{addr}), Plugins: []string{"modbus"}}, nil)
	if !errors.Is(err, ErrRunnerNoMatchingPlugins) {
		t.Fatalf("err = %v, want ErrRunnerNoMatchingPlugins", err)
	}
	stop()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.started != 0 || accepted.Load() != 0 {
		t.Fatalf("started %d runs and made %d connections, want 0 and 0", rec.started, accepted.Load())
	}
}

// TestDBRunRecorder_RecordOutlivesCancel: the finding of a probe that
// was in flight when its job was cancelled is still stored.
func TestDBRunRecorder_RecordOutlivesCancel(t *testing.T) {
	q := &ctxQuerier{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := dbRunRecorder{w: repo.NewRunWriter(q)}.Record(ctx, "11111111-1111-4111-8111-111111111111",
		core.Finding{Protocol: "modbus", Severity: core.SeverityLow, Score: 10},
		core.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: 502})
	if err != nil || q.rows != 1 || q.execs != 1 || q.deadCtx != 0 {
		t.Fatalf("err %v; %d target upserts, %d inserts, %d with a cancelled context; want nil, 1, 1, 0", err, q.rows, q.execs, q.deadCtx)
	}
}

// panicProtocol is a plugin whose probe panics, as one could on bytes
// a device crafted.
type panicProtocol struct{}

func (panicProtocol) Metadata() core.PluginMetadata {
	return core.PluginMetadata{Name: "panic-test"}
}
func (panicProtocol) Probe(context.Context, core.Target) (*core.Finding, error) {
	panic("hostile bytes")
}
func (panicProtocol) REPL(context.Context, *core.Session) error { return nil }
func (panicProtocol) ProxyHandler() core.ProxyHandler           { return nil }

// TestScanRunner_ProbePanicFailsJob: a probe panic through the real
// dispatch neither takes the process down nor passes for a clean run:
// it is counted, and Run would fail the job (re-audit of PITF-094).
func TestScanRunner_ProbePanicFailsJob(t *testing.T) {
	plugin := core.Plugin{PluginMetadata: core.PluginMetadata{Name: "panic-test"}, Factory: func() core.Protocol { return panicProtocol{} }}
	state := newRunState(1, 0, 2)
	targets := []core.Target{
		{Address: netip.MustParseAddr("127.0.0.1"), Port: 1},
		{Address: netip.MustParseAddr("127.0.0.1"), Port: 2},
	}
	if n := state.dispatchAll(context.Background(), []core.Plugin{plugin}, targets, func(scanorch.Stats, map[string]int) {}); n != 1 {
		t.Fatalf("dispatched %d plugins, want 1", n)
	}
	if got := state.panics.Load(); got != 2 {
		t.Fatalf("%d panics counted, want 2", got)
	}
}
