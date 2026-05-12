package scanorch

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Scheduler walks the ScheduleStore on a tick interval and
// fires due schedules by Submitting Jobs to the ScanStore. One
// long-lived goroutine per Scheduler instance; cmd_serve
// spawns one when --scan-store != off.
//
// Tick interval is 30s by default (clamped [10s, 5min]) — fast
// enough that an "every 60s" schedule fires on its expected
// cadence with at most a 30s slip, slow enough that a quiet
// store doesn't burn CPU.
type Scheduler struct {
	// ScheduleStore holds the saved templates. Required.
	ScheduleStore ScheduleStore
	// ScanStore is where firing schedules drop their
	// auto-submitted Jobs. Required.
	ScanStore Store
	// TickInterval bounds how often Run() walks the schedule
	// store. Clamped to [10s, 5min]; defaults to 30s.
	TickInterval time.Duration
	// OnFire (optional) is invoked after every successful
	// auto-fire. cmd_serve uses this to log the fire event;
	// metrics implementations can wire a counter here.
	OnFire func(scheduleID string, job Job)
	// OnFireError (optional) is invoked when a Submit fails
	// during a fire attempt. The Scheduler doesn't retry
	// internally — the next tick re-evaluates the schedule.
	OnFireError func(scheduleID string, err error)
}

// Sentinels.
var (
	// ErrSchedulerNoStore means a Scheduler was constructed
	// without a ScheduleStore.
	ErrSchedulerNoScheduleStore = errors.New("scanorch: scheduler requires a ScheduleStore")
	// ErrSchedulerNoScanStore means the Scheduler has no
	// place to submit fired jobs.
	ErrSchedulerNoScanStore = errors.New("scanorch: scheduler requires a ScanStore")
)

// Run blocks until ctx is cancelled, walking the schedule
// store each tick. Returns ctx.Err() on exit.
//
// Concurrency: the Scheduler runs SEQUENTIALLY through
// schedules per tick — no parallel goroutine per fire. A slow
// Submit (e.g. DBStore lock contention) delays subsequent
// fires by the round-trip time but doesn't break ordering or
// exceed the worker pool. For deployments that need parallel
// firing, a future cycle adds a configurable concurrency knob.
func (s *Scheduler) Run(ctx context.Context) error {
	if s.ScheduleStore == nil {
		return ErrSchedulerNoScheduleStore
	}
	if s.ScanStore == nil {
		return ErrSchedulerNoScanStore
	}
	interval := s.TickInterval
	if interval < 10*time.Second || interval > 5*time.Minute {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// tick walks every schedule, identifies the due ones, and
// fires them via ScanStore.Submit. Errors are surfaced via
// OnFireError but don't terminate the tick; the next tick
// re-evaluates.
func (s *Scheduler) tick(ctx context.Context) {
	schedules, err := s.ScheduleStore.List(ctx)
	if err != nil {
		if s.OnFireError != nil {
			s.OnFireError("", fmt.Errorf("scheduler: list: %w", err))
		}
		return
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, sched := range schedules {
		if !sched.IsDue(now) {
			continue
		}
		s.fire(ctx, sched, now)
	}
}

// fire submits a Job from the schedule's template and stamps
// LastFiredAt. Stamps before the Submit lands so a Submit
// failure doesn't leave the schedule in a "fire on every
// tick" loop — the operator's next tick computes the right
// "due" check from the new timestamp. (A failure that needs
// a retry is the operator's call to make manually; tight
// retry loops in the scheduler are a footgun.)
func (s *Scheduler) fire(ctx context.Context, sched ScanSchedule, now time.Time) {
	if err := s.ScheduleStore.MarkFired(ctx, sched.ID, now); err != nil {
		if s.OnFireError != nil {
			s.OnFireError(sched.ID, fmt.Errorf("scheduler: mark-fired: %w", err))
		}
		// Don't proceed to Submit — if we can't track the
		// firing, we'd loop on the next tick.
		return
	}
	// v1.92: SubmitFromSchedule records sched.ID on the job so
	// GET /api/v1/schedules/{id}/runs can list this firing's
	// run history.
	job, err := s.ScanStore.SubmitFromSchedule(ctx, sched.Template, sched.Operator, sched.ID)
	if err != nil {
		if s.OnFireError != nil {
			s.OnFireError(sched.ID, err)
		}
		return
	}
	if s.OnFire != nil {
		s.OnFire(sched.ID, job)
	}
}

// Tick is exposed for tests so they can deterministically
// trigger one walk without waiting for the goroutine ticker.
// Production code uses Run; Tick is a test affordance.
func (s *Scheduler) Tick(ctx context.Context) {
	if s.ScheduleStore == nil || s.ScanStore == nil {
		return
	}
	s.tick(ctx)
}

// FUTURE: a single-shot "fire all due schedules now" CLI verb
// could expose Tick directly; an advisory-lock wrapper around
// MarkFired would let multiple `serve` instances race safely
// against a shared DB-backed ScheduleStore. Both deferred —
// the in-memory v1.70 store is single-process by design.
