package scanorch_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// fakeRunner returns the configured stats + err. blockUntil, if
// non-nil, blocks until the channel is closed (lets tests
// pace the runner against ctx cancellation).
type fakeRunner struct {
	stats      scanorch.Stats
	err        error
	blockUntil chan struct{}
	calls      atomic.Int32
}

func (f *fakeRunner) Run(ctx context.Context, _ scanorch.Job) (scanorch.Stats, error) {
	f.calls.Add(1)
	if f.blockUntil != nil {
		select {
		case <-f.blockUntil:
		case <-ctx.Done():
			return scanorch.Stats{}, ctx.Err()
		}
	}
	return f.stats, f.err
}

// TestWorker_HappyPath: queued → running → completed with stats.
func TestWorker_HappyPath(t *testing.T) {
	store := scanorch.NewMemoryStore()
	job, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	runner := &fakeRunner{stats: scanorch.Stats{TargetsSeen: 10, TargetsScanned: 10, FindingsCount: 3}}
	w := &scanorch.Worker{Store: store, Runner: runner}
	final, err := w.Process(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Process err = %v", err)
	}
	if final.State != scanorch.StateCompleted {
		t.Errorf("State = %q, want completed", final.State)
	}
	if final.Stats != (scanorch.Stats{TargetsSeen: 10, TargetsScanned: 10, FindingsCount: 3}) {
		t.Errorf("Stats = %+v", final.Stats)
	}
	if final.FinishedAt.IsZero() {
		t.Errorf("FinishedAt should be populated")
	}
	if runner.calls.Load() != 1 {
		t.Errorf("runner called %d times, want 1", runner.calls.Load())
	}
}

// TestWorker_RunnerError: queued → running → failed with error
// message + partial stats preserved.
func TestWorker_RunnerError(t *testing.T) {
	store := scanorch.NewMemoryStore()
	job, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	partialStats := scanorch.Stats{TargetsSeen: 5, TargetsScanned: 2}
	runner := &fakeRunner{stats: partialStats, err: errors.New("input file not found")}
	w := &scanorch.Worker{Store: store, Runner: runner}
	final, err := w.Process(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Process err = %v", err)
	}
	if final.State != scanorch.StateFailed {
		t.Errorf("State = %q, want failed", final.State)
	}
	if final.Error != "input file not found" {
		t.Errorf("Error = %q", final.Error)
	}
	if final.Stats != partialStats {
		t.Errorf("Stats = %+v, want partial %+v", final.Stats, partialStats)
	}
}

// TestWorker_Cancellation: ctx cancellation mid-run yields
// StateCancelled.
func TestWorker_Cancellation(t *testing.T) {
	store := scanorch.NewMemoryStore()
	job, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	block := make(chan struct{})
	runner := &fakeRunner{blockUntil: block}
	w := &scanorch.Worker{Store: store, Runner: runner}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct {
		job scanorch.Job
		err error
	}, 1)
	go func() {
		j, err := w.Process(ctx, job.ID)
		done <- struct {
			job scanorch.Job
			err error
		}{j, err}
	}()
	// Give the runner a moment to start, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()
	close(block) // unblock so the runner returns
	res := <-done
	if res.err != nil {
		t.Fatalf("Process err = %v", res.err)
	}
	if res.job.State != scanorch.StateCancelled {
		t.Errorf("State = %q, want cancelled", res.job.State)
	}
}

// TestWorker_NotQueuedRefuses: a job already in StateRunning
// can't be re-claimed. Protects against double-claim races
// when multiple workers race for the same job.
func TestWorker_NotQueuedRefuses(t *testing.T) {
	store := scanorch.NewMemoryStore()
	job, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	// Pre-claim by transitioning to running.
	_, _ = store.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	w := &scanorch.Worker{Store: store, Runner: &fakeRunner{}}
	_, err := w.Process(context.Background(), job.ID)
	if err == nil {
		t.Fatal("expected claim error")
	}
	if !errors.Is(err, scanorch.ErrInvalidTransition) {
		t.Errorf("err = %v, want ErrInvalidTransition", err)
	}
}

// TestWorker_PanicRecovered: a panicking runner doesn't take
// down the worker; the job ends up failed with a synthetic
// error and the panic value is forwarded to the handler.
func TestWorker_PanicRecovered(t *testing.T) {
	store := scanorch.NewMemoryStore()
	job, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	var capturedID string
	var capturedPanic interface{}
	w := &scanorch.Worker{
		Store: store,
		Runner: scanorch.JobRunnerFunc(func(_ context.Context, _ scanorch.Job) (scanorch.Stats, error) {
			panic("boom")
		}),
		PanicHandler: func(jobID string, panicValue interface{}) {
			capturedID = jobID
			capturedPanic = panicValue
		},
	}
	final, err := w.Process(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("Process err = %v", err)
	}
	if final.State != scanorch.StateFailed {
		t.Errorf("State = %q, want failed", final.State)
	}
	if capturedID != job.ID {
		t.Errorf("PanicHandler jobID = %q, want %q", capturedID, job.ID)
	}
	if capturedPanic != "boom" {
		t.Errorf("PanicHandler value = %v", capturedPanic)
	}
}

// TestWorker_NoStore returns the sentinel.
func TestWorker_NoStore(t *testing.T) {
	w := &scanorch.Worker{Runner: &fakeRunner{}}
	_, err := w.Process(context.Background(), "any")
	if !errors.Is(err, scanorch.ErrWorkerNoStore) {
		t.Errorf("err = %v, want ErrWorkerNoStore", err)
	}
}

// TestWorker_NoRunner returns the sentinel.
func TestWorker_NoRunner(t *testing.T) {
	w := &scanorch.Worker{Store: scanorch.NewMemoryStore()}
	_, err := w.Process(context.Background(), "any")
	if !errors.Is(err, scanorch.ErrWorkerNoRunner) {
		t.Errorf("err = %v, want ErrWorkerNoRunner", err)
	}
}

// TestWorker_ProcessAll drains every queued job in the store.
func TestWorker_ProcessAll(t *testing.T) {
	store := scanorch.NewMemoryStore()
	for i := 0; i < 5; i++ {
		_, _ = store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	}
	w := &scanorch.Worker{Store: store, Runner: &fakeRunner{stats: scanorch.Stats{TargetsScanned: 1}}}
	processed, err := w.ProcessAll(context.Background())
	if err != nil {
		t.Fatalf("ProcessAll err = %v", err)
	}
	if processed != 5 {
		t.Errorf("processed = %d, want 5", processed)
	}
	jobs, _ := store.List(context.Background(), 100)
	for _, j := range jobs {
		if j.State != scanorch.StateCompleted {
			t.Errorf("job %s state = %q, want completed", j.ID, j.State)
		}
	}
}

// TestWorker_ProcessAll_SkipsNonQueued: a mix of states only
// drains the queued ones.
func TestWorker_ProcessAll_SkipsNonQueued(t *testing.T) {
	store := scanorch.NewMemoryStore()
	queued1, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	running, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	_, _ = store.Transition(context.Background(), running.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	queued2, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	w := &scanorch.Worker{Store: store, Runner: &fakeRunner{}}
	processed, err := w.ProcessAll(context.Background())
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if processed != 2 {
		t.Errorf("processed = %d, want 2 (only queued)", processed)
	}
	q1, _ := store.Get(context.Background(), queued1.ID)
	q2, _ := store.Get(context.Background(), queued2.ID)
	r, _ := store.Get(context.Background(), running.ID)
	if q1.State != scanorch.StateCompleted || q2.State != scanorch.StateCompleted {
		t.Errorf("queued jobs not completed: q1=%s q2=%s", q1.State, q2.State)
	}
	if r.State != scanorch.StateRunning {
		t.Errorf("pre-running job advanced unexpectedly: %s", r.State)
	}
}

// TestPool_BasicSubmit submits jobs into a 2-worker pool and
// verifies they all complete.
func TestPool_BasicSubmit(t *testing.T) {
	store := scanorch.NewMemoryStore()
	const N = 6
	ids := make([]string, N)
	for i := 0; i < N; i++ {
		j, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
		ids[i] = j.ID
	}
	w := &scanorch.Worker{Store: store, Runner: &fakeRunner{}}
	pool := scanorch.NewPool(w, 2)
	pool.Start(context.Background())
	defer pool.Stop()
	for _, id := range ids {
		if err := pool.Submit(context.Background(), id); err != nil {
			t.Fatalf("Submit %s err = %v", id, err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		for _, id := range ids {
			j, _ := store.Get(context.Background(), id)
			if j.State != scanorch.StateCompleted {
				all = false
				break
			}
		}
		if all {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("not all jobs completed within 2s")
}

// TestPool_StopRefusesNewWork: after Stop, Submit returns
// ErrPoolClosed.
func TestPool_StopRefusesNewWork(t *testing.T) {
	w := &scanorch.Worker{Store: scanorch.NewMemoryStore(), Runner: &fakeRunner{}}
	pool := scanorch.NewPool(w, 1)
	pool.Start(context.Background())
	pool.Stop()
	err := pool.Submit(context.Background(), "any")
	if !errors.Is(err, scanorch.ErrPoolClosed) {
		t.Errorf("err = %v, want ErrPoolClosed", err)
	}
}

// TestPool_ConcurrencyClamp: extreme values clamp to [1, 64].
// Smoke test: just verify NewPool / Start / Stop don't panic
// for adversarial concurrency values.
func TestPool_ConcurrencyClamp(_ *testing.T) {
	w := &scanorch.Worker{Store: scanorch.NewMemoryStore(), Runner: &fakeRunner{}}
	for _, n := range []int{0, -1, 100} {
		pool := scanorch.NewPool(w, n)
		pool.Start(context.Background())
		pool.Stop()
	}
}

// TestDrain_StopsOnContextCancel: Drain returns ctx.Err()
// after cancellation.
func TestDrain_StopsOnContextCancel(t *testing.T) {
	w := &scanorch.Worker{Store: scanorch.NewMemoryStore(), Runner: &fakeRunner{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Drain(ctx, 50*time.Millisecond) }()
	time.Sleep(120 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain did not return after cancel")
	}
}

// TestJobRunnerFunc adapts a function literal.
func TestJobRunnerFunc(t *testing.T) {
	var called bool
	runner := scanorch.JobRunnerFunc(func(_ context.Context, _ scanorch.Job) (scanorch.Stats, error) {
		called = true
		return scanorch.Stats{TargetsSeen: 7}, nil
	})
	stats, err := runner.Run(context.Background(), scanorch.Job{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !called {
		t.Errorf("function not called")
	}
	if stats.TargetsSeen != 7 {
		t.Errorf("Stats = %+v", stats)
	}
}

// silence unused imports
var _ sync.Mutex
