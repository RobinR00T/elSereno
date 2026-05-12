package scanorch

import (
	"context"
	"errors"
	"time"
)

// AuditPruner (v1.87+) is a long-lived goroutine that
// periodically invokes AuditStore.PruneOlderThan with a
// rolling cutoff. cmd_serve spawns one when
// --audit-retention-days > 0 so operators don't have to
// cron a curl call manually.
//
// Design mirrors Scheduler (v1.70): Run(ctx) blocks until
// cancellation, with OnPrune / OnError callbacks for
// observability. Single instance per serve process.
type AuditPruner struct {
	// AuditStore is the target of PruneOlderThan. Required.
	AuditStore ScheduleAuditStore
	// RetentionPeriod is the cutoff lookback — events with
	// OccurredAt < (now - RetentionPeriod) are deleted on
	// each tick. Required > 0; clamped to ≥ 1m
	// defensively to prevent operator footgun (deleting
	// brand-new events).
	RetentionPeriod time.Duration
	// Interval is how often Run() prunes. Clamped to
	// [1m, 7d]; defaults to 24h. Most retention policies
	// don't need sub-day granularity.
	Interval time.Duration
	// Now (optional, test seam) returns the reference
	// timestamp. Defaults to time.Now().UTC().
	Now func() time.Time
	// OnPrune (optional) fires after every prune with the
	// number of deleted rows. cmd_serve wires this to
	// stderr logging.
	OnPrune func(deletedCount int64, cutoff time.Time)
	// OnError (optional) fires when PruneOlderThan returns
	// an error. The pruner doesn't retry internally — next
	// tick re-attempts.
	OnError func(err error)
	// ScheduleStore (v1.89+, optional) lets the pruner honour
	// per-schedule AuditRetentionDays overrides. When non-nil,
	// each tick lists schedules + builds an
	// (id → schedule-specific cutoff) map for
	// PruneWithOverrides. Nil → behaves identically to v1.87
	// (one global cutoff via PruneOlderThan).
	//
	// Schedules with AuditRetentionDays == 0 contribute to
	// the global cutoff (back-compat: pre-v1.89 schedules
	// inherit the global retention naturally). Only > 0
	// values produce per-schedule overrides.
	ScheduleStore ScheduleStore
	// AdvisoryLockKey (v1.90+, optional) is the Postgres
	// advisory lock key used to serialise concurrent pruners
	// across multiple serve processes. When > 0 AND the
	// AuditStore implements AdvisoryLockedAuditStore, each
	// tick attempts pg_try_advisory_xact_lock(key) inside a
	// transaction and only prunes if acquired.
	//
	// 0 (default) → no locking. Safe for single-process
	// deployments (the dominant case). Multi-process serve
	// against a shared DB should set AuditPrunerLockKey so
	// only one instance prunes at a time.
	//
	// Stores that don't implement AdvisoryLockedAuditStore
	// (in-memory, test fakes) silently ignore this field.
	AdvisoryLockKey int64
	// OnLockSkipped (v1.90+, optional) fires when a tick
	// observed that another pruner held the advisory lock
	// and this tick skipped cleanly. cmd_serve wires this
	// to stderr logging so operators can see the
	// coordination from logs.
	OnLockSkipped func(key int64)
	// OnTick (v1.94+, optional) fires on every tick after
	// OnPrune / OnLockSkipped / OnError. Duration is the
	// wall-clock cost of the tick (prune SQL + lock acquire
	// if any). cmd_serve wires this to the
	// elsereno_audit_pruner_tick_duration_seconds histogram
	// so operators can detect "the audit table grew enough
	// that ticks are slowing" before it becomes incident-
	// shaped.
	OnTick func(duration time.Duration)
}

// Sentinels.
var (
	// ErrAuditPrunerNoStore means the pruner was
	// constructed without an AuditStore.
	ErrAuditPrunerNoStore = errors.New("scanorch: audit pruner requires an AuditStore")
	// ErrAuditPrunerNoRetention means RetentionPeriod was
	// zero or negative.
	ErrAuditPrunerNoRetention = errors.New("scanorch: audit pruner requires a positive RetentionPeriod")
)

// audit-pruner clamping bounds.
const (
	pruneMinRetention = time.Minute
	pruneMinInterval  = time.Minute
	pruneMaxInterval  = 7 * 24 * time.Hour
)

// Run blocks until ctx is cancelled, pruning each tick.
// Returns ctx.Err() on exit. ErrAuditPrunerNo* on bad
// construction.
func (p *AuditPruner) Run(ctx context.Context) error {
	if p.AuditStore == nil {
		return ErrAuditPrunerNoStore
	}
	if p.RetentionPeriod <= 0 {
		return ErrAuditPrunerNoRetention
	}
	retention := p.RetentionPeriod
	if retention < pruneMinRetention {
		retention = pruneMinRetention
	}
	interval := p.Interval
	if interval < pruneMinInterval {
		interval = 24 * time.Hour
	}
	if interval > pruneMaxInterval {
		interval = pruneMaxInterval
	}
	nowFn := p.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Eager first prune so the pruner doesn't wait a full
	// interval after process start. Especially useful on a
	// 24h cadence — the operator restarting serve doesn't
	// have to wait a day for the first cleanup.
	p.tick(ctx, retention, nowFn)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.tick(ctx, retention, nowFn)
		}
	}
}

// tick computes cutoff = now - retention and calls
// PruneOlderThan. Errors surface via OnError; the next
// tick re-attempts.
//
// v1.89+: when ScheduleStore is set, build a
// (schedule_id → per-schedule cutoff) map from each
// schedule's AuditRetentionDays, then call
// PruneWithOverrides instead. Schedules with retention 0
// inherit the global cutoff naturally (no override entry).
//
// v1.90+: when AdvisoryLockKey > 0 AND the AuditStore
// implements AdvisoryLockedAuditStore, the prune runs
// inside a pg_try_advisory_xact_lock transaction.
// Lock-already-held → tick skips cleanly + OnLockSkipped
// fires. Multi-process serve deployments wire this so
// only one instance does the work per cutoff.
func (p *AuditPruner) tick(ctx context.Context, retention time.Duration, nowFn func() time.Time) {
	now := nowFn()
	// v1.94: measure tick duration via wall-clock (not nowFn —
	// nowFn is the cutoff fixture, not a real clock; using
	// time.Now keeps histogram observations honest even with
	// the test-seam time travel pattern).
	start := time.Now()
	defer func() {
		if p.OnTick != nil {
			p.OnTick(time.Since(start))
		}
	}()
	globalCutoff := now.Add(-retention)
	overrides := p.collectOverrides(ctx, now)
	count, acquired, err := p.runPrune(ctx, globalCutoff, overrides)
	if err != nil {
		if p.OnError != nil {
			p.OnError(err)
		}
		return
	}
	if !acquired {
		if p.OnLockSkipped != nil {
			p.OnLockSkipped(p.AdvisoryLockKey)
		}
		return
	}
	if p.OnPrune != nil {
		p.OnPrune(count, globalCutoff)
	}
}

// runPrune dispatches the v1.86 / v1.89 / v1.90 prune variants:
//
//	v1.86 (no overrides, no lock) → PruneOlderThan
//	v1.89 (overrides, no lock)    → PruneWithOverrides
//	v1.90 (lock + overrides)      → PruneWithLock (when supported)
//
// Returns (count, acquired, err). acquired=false only when the
// advisory-lock path was attempted + another caller held the
// lock. The non-locked paths always report acquired=true.
func (p *AuditPruner) runPrune(ctx context.Context, globalCutoff time.Time, overrides map[string]time.Time) (int64, bool, error) {
	if p.AdvisoryLockKey > 0 {
		if locker, ok := p.AuditStore.(AdvisoryLockedAuditStore); ok {
			return locker.PruneWithLock(ctx, p.AdvisoryLockKey, globalCutoff, overrides)
		}
	}
	if len(overrides) > 0 {
		c, err := p.AuditStore.PruneWithOverrides(ctx, globalCutoff, overrides)
		return c, true, err
	}
	c, err := p.AuditStore.PruneOlderThan(ctx, globalCutoff)
	return c, true, err
}

// collectOverrides (v1.89+) walks the ScheduleStore (when set)
// and builds the per-schedule cutoff map for PruneWithOverrides.
// Schedules with AuditRetentionDays > 0 contribute one entry
// keyed by ID; those with 0/unset inherit the global cutoff.
//
// A ScheduleStore.List error surfaces via OnError + falls back
// to global-only (empty overrides). Better to over-prune
// briefly than crash the pruner — next tick re-attempts.
func (p *AuditPruner) collectOverrides(ctx context.Context, now time.Time) map[string]time.Time {
	if p.ScheduleStore == nil {
		return nil
	}
	schedules, err := p.ScheduleStore.List(ctx)
	if err != nil {
		if p.OnError != nil {
			p.OnError(err)
		}
		return nil
	}
	overrides := make(map[string]time.Time, len(schedules))
	for _, s := range schedules {
		if s.AuditRetentionDays > 0 {
			overrides[s.ID] = now.Add(-time.Duration(s.AuditRetentionDays) * 24 * time.Hour)
		}
	}
	if len(overrides) == 0 {
		return nil
	}
	return overrides
}

// Tick is a test affordance — single-shot prune without
// the ticker goroutine. Mirrors Scheduler.Tick.
func (p *AuditPruner) Tick(ctx context.Context) {
	if p.AuditStore == nil || p.RetentionPeriod <= 0 {
		return
	}
	retention := p.RetentionPeriod
	if retention < pruneMinRetention {
		retention = pruneMinRetention
	}
	nowFn := p.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	p.tick(ctx, retention, nowFn)
}
