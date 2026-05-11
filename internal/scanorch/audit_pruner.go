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
func (p *AuditPruner) tick(ctx context.Context, retention time.Duration, nowFn func() time.Time) {
	cutoff := nowFn().Add(-retention)
	count, err := p.AuditStore.PruneOlderThan(ctx, cutoff)
	if err != nil {
		if p.OnError != nil {
			p.OnError(err)
		}
		return
	}
	if p.OnPrune != nil {
		p.OnPrune(count, cutoff)
	}
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
