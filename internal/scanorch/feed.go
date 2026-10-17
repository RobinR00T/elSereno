package scanorch

import (
	"context"
	"log"
	"time"
)

// Feed hands the store's queued jobs to the pool, oldest first, every
// interval, until ctx is done. Until 2026-10-17 serve started the pool
// and nothing submitted to it, so every scan queued from the dashboard,
// the API or a schedule stayed queued forever (PITF-094).
//
// Only jobs created at or after since run. serve passes its own start
// time, so the backlog a database collected while nothing ran it (or
// the jobs a stopped serve left queued) does not fire as a burst of
// real scans when serve starts: those jobs stay queued, and Feed logs
// how many once. Zero since runs every queued job.
//
// A job is submitted once: Feed remembers the IDs it handed over and
// forgets one when the job is no longer queued (a worker claimed it,
// or it was cancelled). A job claimed by another process is refused by
// Process's queued→running transition, so two serve processes on one
// database do not run a job twice. A failed listing is logged and
// retried on the next tick. The interval is clamped to [50ms, 1h];
// zero or out of range means 1s.
func (p *Pool) Feed(ctx context.Context, store Store, since time.Time, interval time.Duration) error {
	if store == nil {
		return ErrWorkerNoStore
	}
	if interval < 50*time.Millisecond || interval > time.Hour {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	f := feeder{pool: p, store: store, since: since, sent: make(map[string]bool)}
	for {
		if err := f.once(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.closed:
			return ErrPoolClosed
		case <-ticker.C:
		}
	}
}

type feeder struct {
	pool  *Pool
	store Store
	since time.Time
	// sent holds the IDs handed to the pool and still queued.
	sent map[string]bool
	// warned is set once the jobs older than since have been logged.
	warned bool
}

// once submits the queued jobs not yet sent. It returns only the
// errors that end Feed (context done, pool stopped).
func (f *feeder) once(ctx context.Context) error {
	jobs, err := f.store.List(ctx, 1000)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("scanorch: feed: list jobs: %v (retrying)", err)
		return nil
	}
	queued := make(map[string]bool, len(jobs))
	stale := 0
	// List returns the newest first; submit the oldest first.
	for i := len(jobs) - 1; i >= 0; i-- {
		job := jobs[i]
		if job.State != StateQueued {
			continue
		}
		if job.CreatedAt.Before(f.since) {
			stale++
			continue
		}
		queued[job.ID] = true
		if f.sent[job.ID] {
			continue
		}
		if err := f.pool.Submit(ctx, job.ID); err != nil {
			return err
		}
		f.sent[job.ID] = true
	}
	for id := range f.sent {
		if !queued[id] {
			delete(f.sent, id)
		}
	}
	if stale > 0 && !f.warned {
		f.warned = true
		log.Printf("scanorch: feed: %d queued jobs predate this start and will not run; "+
			"cancel them (POST /api/v1/scans/{id}/cancel) or submit them again", stale)
	}
	return nil
}
