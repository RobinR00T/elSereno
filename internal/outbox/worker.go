package outbox

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// ErrStopped is returned by Worker.Run when Stop is called.
var ErrStopped = errors.New("outbox: worker stopped")

// Entry is one pending delivery.
type Entry struct {
	ID       string
	Kind     string
	Payload  []byte
	Attempts int
	LastErr  error
	NextTry  time.Time
}

// Store is the minimal interface Worker needs. Either a DB-backed or
// a file-backed implementation plugs in here.
type Store interface {
	// Claim reserves up to `max` due entries for delivery. The
	// implementation is responsible for isolation (e.g. SELECT FOR
	// UPDATE SKIP LOCKED on Postgres).
	Claim(ctx context.Context, max int, now time.Time) ([]*Entry, error)

	// Ack marks the entry as delivered.
	Ack(ctx context.Context, e *Entry) error

	// Fail records a transient failure. If `attempts` has reached the
	// store's cap, the implementation moves the row to the dead-letter
	// table/file.
	Fail(ctx context.Context, e *Entry, maxAttempts int) error

	// Enqueue inserts a new entry (tests and CLI wrappers).
	Enqueue(ctx context.Context, e *Entry) error
}

// Deliverer is the function that attempts to send one entry. Return
// nil on success, a transient error (retryable) otherwise. Return
// errors.Is(ErrPermanent) for non-retryable failures; those go
// straight to dead-letter.
type Deliverer func(ctx context.Context, e *Entry) error

// ErrPermanent signals the worker that an entry must not be retried.
var ErrPermanent = errors.New("outbox: permanent failure")

// Worker polls the Store and hands entries to the Deliverer. It is
// safe to run in a goroutine; Stop returns only when the inner loop
// exits.
type Worker struct {
	Store        Store
	Deliverer    Deliverer
	MaxAttempts  int
	PollInterval time.Duration
	BatchSize    int
	BaseBackoff  time.Duration
	MaxBackoff   time.Duration

	mu      sync.Mutex
	stopCh  chan struct{}
	stopped bool
}

// NewWorker returns a Worker with sensible defaults.
func NewWorker(store Store, deliverer Deliverer) *Worker {
	return &Worker{
		Store:        store,
		Deliverer:    deliverer,
		MaxAttempts:  10,
		PollInterval: 1 * time.Second,
		BatchSize:    16,
		BaseBackoff:  2 * time.Second,
		MaxBackoff:   5 * time.Minute,
		stopCh:       make(chan struct{}),
	}
}

// Run polls until ctx is cancelled or Stop is called.
func (w *Worker) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.stopCh:
			return ErrStopped
		default:
		}
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.stopCh:
			return ErrStopped
		case <-time.After(w.PollInterval):
		}
	}
}

// Stop signals Run to exit. Safe to call concurrently; idempotent.
func (w *Worker) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.stopped = true
	close(w.stopCh)
}

func (w *Worker) tick(ctx context.Context) {
	entries, err := w.Store.Claim(ctx, w.BatchSize, time.Now())
	if err != nil {
		return
	}
	for _, e := range entries {
		err := w.Deliverer(ctx, e)
		switch {
		case err == nil:
			_ = w.Store.Ack(ctx, e)
		case errors.Is(err, ErrPermanent):
			// Permanent errors skip straight to dead-letter.
			e.Attempts = w.MaxAttempts
			e.LastErr = err
			_ = w.Store.Fail(ctx, e, w.MaxAttempts)
		default:
			e.Attempts++
			e.LastErr = err
			e.NextTry = time.Now().Add(w.backoff(e.Attempts))
			_ = w.Store.Fail(ctx, e, w.MaxAttempts)
		}
	}
}

// backoff returns exponential backoff + jitter capped at MaxBackoff.
func (w *Worker) backoff(attempts int) time.Duration {
	d := w.BaseBackoff
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= w.MaxBackoff {
			d = w.MaxBackoff
			break
		}
	}
	jitter := time.Duration(rand.Float64() * float64(d) * 0.25) // #nosec G404 -- jitter, not security
	return d + jitter
}

// StringErr is a helper for tests that need to set Entry.LastErr to a
// sentinel string.
func StringErr(s string) error { return fmt.Errorf("%s", s) }
