package scanorch

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ProgressReporter is the callback a JobRunner uses to publish
// mid-run Stats snapshots. Worker passes a no-op reporter when
// no listener is wired; cmd_serve wires a throttled SSE publish.
//
// The runner is expected to call this on a high-frequency cadence
// (every drained scanner event); the Worker / wiring layer
// decides whether to actually surface each snapshot. Keeping the
// throttle policy on the listener side means the runner doesn't
// need to know about timers + the same runner can serve a
// dashboard (heavy throttle) and a CLI watcher (lighter
// throttle) without code change.
//
// v1.66+: byPlugin (optional, may be nil for runners that don't
// track per-plugin breakdown) carries the per-plugin findings
// count. The map is owned by the runner; the listener should
// copy if it needs to retain.
type ProgressReporter func(stats Stats, byPlugin map[string]int)

// JobRunner is the interface a Worker uses to actually execute
// a Job. The orchestration shell stays decoupled from the
// scanner / input-parser concrete types so:
//
//   - Tests can supply a fake runner without dragging the
//     scanner package + plugin registry into scanorch's test
//     graph.
//   - Future runners (e.g., one that dispatches across multiple
//     scanner workers, or one that runs in a sandboxed
//     subprocess) can be swapped in.
//
// The runner takes the queued Job and returns the final Stats +
// any error. The Worker handles state transitions; the runner
// only owns the actual scan work.
//
// **v1.65+**: report is invoked with current Stats snapshots as
// the run progresses. Implementations are encouraged to call
// report on every probe completion; the listener side throttles.
// Pre-v1.65 runners that don't call report at all still work
// (the Worker no-ops on missing reports).
//
// **v1.66+**: Run returns the per-plugin findings breakdown
// alongside Stats. Single-plugin runners may return nil
// (FindingsCount in Stats is sufficient).
type JobRunner interface {
	// Run executes job and returns the resulting Stats +
	// per-plugin findings breakdown + error. Implementations
	// should respect ctx cancellation and bail promptly when
	// ctx is Done. Returning a non-nil error transitions the
	// job to StateFailed; nil error + non-cancelled ctx
	// transitions to StateCompleted.
	Run(ctx context.Context, job Job, report ProgressReporter) (Stats, map[string]int, error)
}

// JobRunnerFunc adapts a plain function to the JobRunner
// interface.
type JobRunnerFunc func(ctx context.Context, job Job, report ProgressReporter) (Stats, map[string]int, error)

// Run implements JobRunner.
func (f JobRunnerFunc) Run(ctx context.Context, job Job, report ProgressReporter) (Stats, map[string]int, error) {
	return f(ctx, job, report)
}

// ErrWorkerNoStore means a Worker was constructed without a
// Store. Required for any state mutation.
var ErrWorkerNoStore = errors.New("scanorch: worker requires a Store")

// ErrWorkerNoRunner means a Worker was constructed without a
// JobRunner. Process() can't dispatch without one.
var ErrWorkerNoRunner = errors.New("scanorch: worker requires a JobRunner")

// Worker drives a job through the queued → running →
// completed | failed | cancelled state transitions. One
// Worker can process many jobs (sequentially via Process,
// or concurrently via independent goroutines each calling
// Process for a different job ID).
//
// Worker is intentionally simple — it doesn't pull from a
// queue or schedule work. The orchestration boundary above
// it (the dashboard, or a future scheduler) calls Process
// with a specific job ID. This separation lets the Worker
// be tested in isolation and lets different scheduling
// strategies (FIFO queue / per-operator priority / etc.)
// be added later without touching Worker internals.
type Worker struct {
	// Store is the persistence interface. Required.
	Store Store
	// Runner is the JobRunner that performs the actual scan.
	// Required.
	Runner JobRunner
	// PanicHandler, if non-nil, is called when Runner.Run
	// panics. The worker recovers the panic, marks the job
	// failed, and surfaces the panic value via this hook
	// (e.g., to forward to the audit log or telemetry).
	PanicHandler func(jobID string, panicValue interface{})
	// OnProgress, if non-nil, is invoked with mid-run Stats +
	// per-plugin findings breakdown from the Runner. The
	// Worker does NOT throttle — it's the listener's
	// responsibility (cmd_serve wires a time-based throttle
	// here). Nil → no-op reporter passed to Runner.Run.
	OnProgress func(jobID string, stats Stats, byPlugin map[string]int)
}

// Process dispatches the job with the given ID. The worker:
//
//  1. Transitions queued → running (refuses if the job isn't
//     queued — protects against double-claims when multiple
//     workers race for the same job).
//  2. Calls Runner.Run with a context derived from ctx.
//  3. On nil error: transitions running → completed with
//     final Stats + per-plugin findings breakdown.
//  4. On non-nil error: transitions running → failed with the
//     error message.
//  5. On ctx cancellation during Run: transitions running →
//     cancelled (the operator-initiated cancellation path).
//
// Returns the final Job state plus any orchestration error
// (NOT the runner's error — that's recorded on the Job and
// returned to nil at this level since the state transition
// succeeded).
func (w *Worker) Process(ctx context.Context, jobID string) (Job, error) {
	if w.Store == nil {
		return Job{}, ErrWorkerNoStore
	}
	if w.Runner == nil {
		return Job{}, ErrWorkerNoRunner
	}
	// Step 1: claim the job.
	claimed, err := w.Store.Transition(ctx, jobID, StateRunning, TransitionFields{})
	if err != nil {
		return Job{}, fmt.Errorf("scanorch: claim job %s: %w", jobID, err)
	}
	// Step 2: run with panic recovery.
	stats, byPlugin, runErr := w.runWithRecover(ctx, claimed)
	// Step 3: terminal transition based on outcome.
	return w.terminate(ctx, jobID, stats, byPlugin, runErr, ctx.Err())
}

// runWithRecover wraps Runner.Run with a panic recovery so a
// misbehaving runner can't take down the whole worker
// goroutine. A panic is reported through PanicHandler (if set)
// and surfaced as a synthetic error.
func (w *Worker) runWithRecover(ctx context.Context, job Job) (stats Stats, byPlugin map[string]int, runErr error) {
	defer func() {
		if r := recover(); r != nil {
			if w.PanicHandler != nil {
				w.PanicHandler(job.ID, r)
			}
			runErr = fmt.Errorf("scanorch: runner panic: %v", r)
		}
	}()
	report := w.makeProgressReporter(job.ID)
	return w.Runner.Run(ctx, job, report)
}

// makeProgressReporter returns a ProgressReporter that forwards
// to OnProgress if set, else a no-op. The Worker does NOT
// throttle — that's the listener's responsibility.
func (w *Worker) makeProgressReporter(jobID string) ProgressReporter {
	if w.OnProgress == nil {
		return func(Stats, map[string]int) {}
	}
	return func(s Stats, by map[string]int) { w.OnProgress(jobID, s, by) }
}

// terminate decides the final state and applies it. Decision
// table:
//
//   - ctx cancelled (regardless of runErr) → StateCancelled
//   - runErr != nil                        → StateFailed
//   - else                                 → StateCompleted
func (w *Worker) terminate(ctx context.Context, jobID string, stats Stats, byPlugin map[string]int, runErr, ctxErr error) (Job, error) {
	var to State
	var fields TransitionFields
	switch {
	case ctxErr != nil:
		to = StateCancelled
		// Don't carry stats or error — cancellation is operator-
		// driven and the partial state isn't meaningful.
	case runErr != nil:
		to = StateFailed
		fields.Error = runErr.Error()
		// Final stats still useful — operator can see how far
		// the scan got before failing.
		fields.Stats = &stats
		fields.FindingsByPlugin = byPlugin
	default:
		to = StateCompleted
		fields.Stats = &stats
		fields.FindingsByPlugin = byPlugin
	}
	// Use a fresh background context for the terminal
	// transition: if the original ctx was cancelled, we still
	// need to record the cancellation in the store. Bound the
	// fallback to a short timeout so a wedged store can't hang
	// the worker forever. Detached deliberately — the parent
	// ctx may be cancelled (that's why we're transitioning to
	// cancelled in the first place).
	storeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:contextcheck // deliberate detach — see comment above
	final, err := w.Store.Transition(storeCtx, jobID, to, fields)
	if err != nil {
		return Job{}, fmt.Errorf("scanorch: terminal transition %s → %s: %w", jobID, to, err)
	}
	_ = ctx // ctx unused after this point — kept in signature for symmetry
	return final, nil
}

// ProcessAll claims and processes every queued job in the
// store, sequentially. Returns the count of jobs processed and
// the first orchestration error encountered (if any). A runner
// error doesn't stop the loop — it's recorded on the
// individual job and the worker moves on.
//
// Useful for the simple "drain the queue once" scheduling
// strategy. Production deployments will want a continuous loop
// via Drain or a goroutine-pool wrapper around Process.
func (w *Worker) ProcessAll(ctx context.Context) (int, error) {
	if w.Store == nil {
		return 0, ErrWorkerNoStore
	}
	jobs, err := w.Store.List(ctx, 1000)
	if err != nil {
		return 0, fmt.Errorf("scanorch: list jobs: %w", err)
	}
	var processed int
	for _, job := range jobs {
		if job.State != StateQueued {
			continue
		}
		if _, perr := w.Process(ctx, job.ID); perr != nil {
			return processed, perr
		}
		processed++
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}
	}
	return processed, nil
}

// Drain runs a continuous polling loop: every poll interval,
// process every queued job in the store. Returns when ctx is
// cancelled. Useful as the default "background worker" that a
// `serve` binary spawns at startup.
//
// pollInterval bounds [50ms, 1h]; defaults to 1s for zero or
// out-of-range values. The bounds prevent CPU-pegging via a
// 0-duration loop and prevent the operator from configuring a
// silently-dead worker via an absurd interval.
func (w *Worker) Drain(ctx context.Context, pollInterval time.Duration) error {
	if w.Store == nil {
		return ErrWorkerNoStore
	}
	if pollInterval < 50*time.Millisecond || pollInterval > time.Hour {
		pollInterval = time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		// Process the current queue immediately + on each tick.
		if _, err := w.ProcessAll(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Pool wraps a Worker with a bounded goroutine pool. Submit a
// job ID via Submit; Pool dispatches via the next free worker
// goroutine (or blocks if all are busy).
//
// Pool is the production-ready scheduling primitive: it caps
// concurrent in-flight jobs (so a flood of submits doesn't OOM
// the host) without burdening callers with goroutine
// management.
type Pool struct {
	worker      *Worker
	concurrency int
	work        chan string
	wg          sync.WaitGroup
	closed      chan struct{}
	closeOnce   sync.Once
}

// NewPool constructs a Pool of the given concurrency around the
// supplied worker. Concurrency is clamped to [1, 64].
func NewPool(worker *Worker, concurrency int) *Pool {
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 64 {
		concurrency = 64
	}
	return &Pool{
		worker:      worker,
		concurrency: concurrency,
		work:        make(chan string, concurrency*2),
		closed:      make(chan struct{}),
	}
}

// Start launches the pool's worker goroutines. Call Stop to
// terminate cleanly.
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.concurrency; i++ {
		p.wg.Add(1)
		go p.run(ctx)
	}
}

// run is one worker goroutine. Drains p.work until ctx is done
// or the channel closes.
func (p *Pool) run(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.closed:
			return
		case jobID, ok := <-p.work:
			if !ok {
				return
			}
			_, _ = p.worker.Process(ctx, jobID)
		}
	}
}

// Submit hands a job ID to a pool worker. Returns
// context.Canceled if ctx is done; ErrPoolClosed if Stop was
// called.
func (p *Pool) Submit(ctx context.Context, jobID string) error {
	// Fast-path the closed check first: an open channel send
	// can race ahead of a buffered closed signal otherwise.
	select {
	case <-p.closed:
		return ErrPoolClosed
	default:
	}
	select {
	case p.work <- jobID:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.closed:
		return ErrPoolClosed
	}
}

// Stop signals every pool worker to exit. Blocks until all
// workers have returned.
func (p *Pool) Stop() {
	p.closeOnce.Do(func() { close(p.closed) })
	p.wg.Wait()
}

// ErrPoolClosed means the pool has been Stopped and refuses
// new work.
var ErrPoolClosed = errors.New("scanorch: pool is closed")
