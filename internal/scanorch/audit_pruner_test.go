package scanorch_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// TestAuditPruner_RunNoStore: missing store sentinel.
func TestAuditPruner_RunNoStore(t *testing.T) {
	p := &scanorch.AuditPruner{RetentionPeriod: time.Hour}
	if err := p.Run(context.Background()); !errors.Is(err, scanorch.ErrAuditPrunerNoStore) {
		t.Errorf("err = %v, want ErrAuditPrunerNoStore", err)
	}
}

// TestAuditPruner_RunNoRetention: zero retention sentinel.
func TestAuditPruner_RunNoRetention(t *testing.T) {
	p := &scanorch.AuditPruner{AuditStore: scanorch.NewMemoryScheduleAuditStore()}
	if err := p.Run(context.Background()); !errors.Is(err, scanorch.ErrAuditPrunerNoRetention) {
		t.Errorf("err = %v, want ErrAuditPrunerNoRetention", err)
	}
}

// TestAuditPruner_Tick_HappyPath: deterministic single tick
// prunes the old events + invokes OnPrune.
func TestAuditPruner_Tick_HappyPath(t *testing.T) {
	store := scanorch.NewMemoryScheduleAuditStore()
	// Append two events, then sleep enough that the prune
	// cutoff (5ms ago) is after both timestamps.
	for i := 0; i < 2; i++ {
		_, err := store.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    "abc",
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("Append err = %v", err)
		}
	}
	// Pruner clamps RetentionPeriod to ≥ 1m, so the easiest
	// way to test "events older than the cutoff" is to set
	// Now to a time far in the future — then cutoff =
	// future - 1min is well after the just-appended events.
	var pruneCount int64
	var pruneCalls int32
	future := time.Now().Add(time.Hour).UTC()
	p := &scanorch.AuditPruner{
		AuditStore:      store,
		RetentionPeriod: time.Minute, // clamp-floor
		Interval:        time.Hour,   // irrelevant for Tick
		Now:             func() time.Time { return future },
		OnPrune: func(count int64, _ time.Time) {
			atomic.AddInt32(&pruneCalls, 1)
			atomic.StoreInt64(&pruneCount, count)
		},
	}
	p.Tick(context.Background())
	if atomic.LoadInt32(&pruneCalls) != 1 {
		t.Errorf("OnPrune calls = %d, want 1", atomic.LoadInt32(&pruneCalls))
	}
	if atomic.LoadInt64(&pruneCount) != 2 {
		t.Errorf("OnPrune count = %d, want 2", atomic.LoadInt64(&pruneCount))
	}
}

// TestAuditPruner_Tick_RespectsRetention: cutoff = now -
// retention. Events newer than retention survive.
func TestAuditPruner_Tick_RespectsRetention(t *testing.T) {
	store := scanorch.NewMemoryScheduleAuditStore()
	for i := 0; i < 3; i++ {
		_, _ = store.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    "abc",
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
	}
	// retention=1h with Now=now → cutoff is 1h ago, so all
	// events (just-appended) survive.
	var pruneCount int64
	p := &scanorch.AuditPruner{
		AuditStore:      store,
		RetentionPeriod: time.Hour,
		Now:             func() time.Time { return time.Now().UTC() },
		OnPrune:         func(c int64, _ time.Time) { atomic.StoreInt64(&pruneCount, c) },
	}
	p.Tick(context.Background())
	if atomic.LoadInt64(&pruneCount) != 0 {
		t.Errorf("pruneCount = %d, want 0 (all events newer than retention)", atomic.LoadInt64(&pruneCount))
	}
	after, _ := store.ListBySchedule(context.Background(), "abc")
	if len(after) != 3 {
		t.Errorf("len = %d, want 3", len(after))
	}
}

// TestAuditPruner_Run_StopsOnCancel: ctx cancellation
// returns ctx.Err() cleanly.
func TestAuditPruner_Run_StopsOnCancel(t *testing.T) {
	p := &scanorch.AuditPruner{
		AuditStore:      scanorch.NewMemoryScheduleAuditStore(),
		RetentionPeriod: time.Hour,
		Interval:        time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled; Run should return immediately
	// after the eager first tick.
	err := p.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestAuditPruner_Tick_NoStore: Tick is a no-op when the
// store is missing (matches Scheduler.Tick).
func TestAuditPruner_Tick_NoStore(_ *testing.T) {
	p := &scanorch.AuditPruner{RetentionPeriod: time.Hour}
	// Should not panic.
	p.Tick(context.Background())
}

// TestAuditPruner_Tick_PropagatesStoreError: store errors
// surface via OnError.
type errAuditStore struct{}

func (errAuditStore) Append(context.Context, scanorch.ScheduleAuditEvent) (scanorch.ScheduleAuditEvent, error) {
	return scanorch.ScheduleAuditEvent{}, nil
}
func (errAuditStore) ListBySchedule(context.Context, string) ([]scanorch.ScheduleAuditEvent, error) {
	return nil, nil
}
func (errAuditStore) PruneOlderThan(context.Context, time.Time) (int64, error) {
	return 0, errors.New("synthetic prune failure")
}
func (errAuditStore) PruneWithOverrides(context.Context, time.Time, map[string]time.Time) (int64, error) {
	return 0, errors.New("synthetic prune failure")
}

func TestAuditPruner_Tick_PropagatesStoreError(t *testing.T) {
	var seenErr error
	p := &scanorch.AuditPruner{
		AuditStore:      errAuditStore{},
		RetentionPeriod: time.Hour,
		OnError:         func(err error) { seenErr = err },
	}
	p.Tick(context.Background())
	if seenErr == nil {
		t.Errorf("OnError not invoked")
	}
}

// TestAuditPruner_Tick_PerScheduleOverride (v1.89+): pruner
// honours per-schedule AuditRetentionDays via the ScheduleStore.
//
// Setup: 2 schedules, one with AuditRetentionDays=0 (inherit
// global, 30 days) and one with AuditRetentionDays=2 (2 days).
// Append 1 event for each schedule with OccurredAt 5 days ago.
// Tick at "now". Expected:
//   - Schedule A (global 30d) → event survives.
//   - Schedule B (override 2d) → event pruned.
func TestAuditPruner_Tick_PerScheduleOverride(t *testing.T) {
	ctx := context.Background()
	scheduleStore := scanorch.NewMemoryScheduleStore()
	schedA, err := scheduleStore.Create(ctx, scanorch.CreateScheduleRequest{
		Name:            "global-retention",
		Template:        scanorch.SubmitRequest{Input: "list:a.txt"},
		IntervalSeconds: 3600,
	}, "alice")
	if err != nil {
		t.Fatalf("Create A err = %v", err)
	}
	schedB, err := scheduleStore.Create(ctx, scanorch.CreateScheduleRequest{
		Name:               "short-retention",
		Template:           scanorch.SubmitRequest{Input: "list:b.txt"},
		IntervalSeconds:    3600,
		AuditRetentionDays: 2,
	}, "alice")
	if err != nil {
		t.Fatalf("Create B err = %v", err)
	}
	if schedB.AuditRetentionDays != 2 {
		t.Fatalf("schedB.AuditRetentionDays = %d, want 2", schedB.AuditRetentionDays)
	}

	auditStore := scanorch.NewMemoryScheduleAuditStore()
	// Append one event per schedule. OccurredAt is stamped by
	// Append at "now"; the pruner uses Now-fixture pushed 5
	// days ahead to make both look 5 days old.
	for _, id := range []string{schedA.ID, schedB.ID} {
		if _, err := auditStore.Append(ctx, scanorch.ScheduleAuditEvent{
			ScheduleID:    id,
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		}); err != nil {
			t.Fatalf("Append for %s err = %v", id, err)
		}
	}

	pruner := &scanorch.AuditPruner{
		AuditStore:      auditStore,
		ScheduleStore:   scheduleStore,
		RetentionPeriod: 30 * 24 * time.Hour,
		Now:             func() time.Time { return time.Now().UTC().Add(5 * 24 * time.Hour) },
	}
	pruner.Tick(ctx)

	// Schedule A: events still listed (global 30d, event 5d old).
	eventsA, err := auditStore.ListBySchedule(ctx, schedA.ID)
	if err != nil {
		t.Fatalf("ListBySchedule A err = %v", err)
	}
	if len(eventsA) != 1 {
		t.Errorf("schedA events after prune = %d, want 1", len(eventsA))
	}
	// Schedule B: pruned (override 2d, event 5d old).
	eventsB, err := auditStore.ListBySchedule(ctx, schedB.ID)
	if err != nil {
		t.Fatalf("ListBySchedule B err = %v", err)
	}
	if len(eventsB) != 0 {
		t.Errorf("schedB events after prune = %d, want 0", len(eventsB))
	}
}

// TestAuditPruner_Tick_NoOverrides_FallsBackToGlobal (v1.89+):
// when no schedule has AuditRetentionDays>0, the pruner
// behaves exactly like v1.87 — single PruneOlderThan call.
func TestAuditPruner_Tick_NoOverrides_FallsBackToGlobal(t *testing.T) {
	ctx := context.Background()
	scheduleStore := scanorch.NewMemoryScheduleStore()
	sched, err := scheduleStore.Create(ctx, scanorch.CreateScheduleRequest{
		Name:            "global-only",
		Template:        scanorch.SubmitRequest{Input: "list:x.txt"},
		IntervalSeconds: 3600,
	}, "alice")
	if err != nil {
		t.Fatalf("Create err = %v", err)
	}
	auditStore := scanorch.NewMemoryScheduleAuditStore()
	if _, err := auditStore.Append(ctx, scanorch.ScheduleAuditEvent{
		ScheduleID:    sched.ID,
		EventType:     scanorch.ScheduleAuditEventForceOverwrite,
		Operator:      "alice",
		PayloadBefore: json.RawMessage(`{}`),
		PayloadAfter:  json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("Append err = %v", err)
	}
	pruner := &scanorch.AuditPruner{
		AuditStore:      auditStore,
		ScheduleStore:   scheduleStore,
		RetentionPeriod: time.Minute,
		Now:             func() time.Time { return time.Now().UTC().Add(24 * time.Hour) },
	}
	pruner.Tick(ctx)
	events, err := auditStore.ListBySchedule(ctx, sched.ID)
	if err != nil {
		t.Fatalf("ListBySchedule err = %v", err)
	}
	if len(events) != 0 {
		t.Errorf("events after prune = %d, want 0 (global cutoff applies)", len(events))
	}
}

// TestAuditPruner_AdvisoryLockKey_FallsBackOnMemory (v1.90+):
// MemoryScheduleAuditStore doesn't implement
// AdvisoryLockedAuditStore. Pruner with AdvisoryLockKey > 0
// must fall through to PruneWithOverrides cleanly — the
// in-memory mode has no multi-process scenario.
func TestAuditPruner_AdvisoryLockKey_FallsBackOnMemory(t *testing.T) {
	ctx := context.Background()
	auditStore := scanorch.NewMemoryScheduleAuditStore()
	if _, err := auditStore.Append(ctx, scanorch.ScheduleAuditEvent{
		ScheduleID:    "abc",
		EventType:     scanorch.ScheduleAuditEventForceOverwrite,
		Operator:      "alice",
		PayloadBefore: json.RawMessage(`{}`),
		PayloadAfter:  json.RawMessage(`{}`),
	}); err != nil {
		t.Fatalf("Append err = %v", err)
	}
	var skipped int32
	pruner := &scanorch.AuditPruner{
		AuditStore:      auditStore,
		RetentionPeriod: time.Minute,
		AdvisoryLockKey: scanorch.AuditPrunerLockKey,
		Now:             func() time.Time { return time.Now().UTC().Add(24 * time.Hour) },
		OnLockSkipped:   func(int64) { atomic.AddInt32(&skipped, 1) },
	}
	pruner.Tick(ctx)
	// Memory store should NOT have triggered the skip path —
	// the pruner falls back to PruneWithOverrides cleanly.
	if atomic.LoadInt32(&skipped) != 0 {
		t.Errorf("OnLockSkipped fired = %d times, want 0 (memory store has no lock)", skipped)
	}
	events, err := auditStore.ListBySchedule(ctx, "abc")
	if err != nil {
		t.Fatalf("ListBySchedule err = %v", err)
	}
	if len(events) != 0 {
		t.Errorf("events after prune = %d, want 0", len(events))
	}
}

// TestAuditPruner_AdvisoryLockKey_LockNotAcquired (v1.90+):
// when the store implements AdvisoryLockedAuditStore + returns
// acquired=false, the pruner skips cleanly + fires
// OnLockSkipped. Uses a fake locking store to simulate the
// "another pruner won the lock" branch without needing a real
// Postgres.
func TestAuditPruner_AdvisoryLockKey_LockNotAcquired(t *testing.T) {
	store := &fakeLockingAuditStore{acquired: false}
	var skipped int32
	pruner := &scanorch.AuditPruner{
		AuditStore:      store,
		RetentionPeriod: time.Minute,
		AdvisoryLockKey: scanorch.AuditPrunerLockKey,
		OnLockSkipped:   func(int64) { atomic.AddInt32(&skipped, 1) },
	}
	pruner.Tick(context.Background())
	if atomic.LoadInt32(&skipped) != 1 {
		t.Errorf("OnLockSkipped fired = %d times, want 1", skipped)
	}
	if store.lockCalls != 1 {
		t.Errorf("PruneWithLock called = %d times, want 1", store.lockCalls)
	}
}

// TestAuditPruner_AdvisoryLockKey_LockAcquired (v1.90+):
// happy path through the locked variant — acquired=true,
// PruneWithLock returns a row count, OnPrune fires.
func TestAuditPruner_AdvisoryLockKey_LockAcquired(t *testing.T) {
	store := &fakeLockingAuditStore{acquired: true, pruneCount: 42}
	var (
		pruneCount int64
		skipped    int32
		seenError  error
	)
	pruner := &scanorch.AuditPruner{
		AuditStore:      store,
		RetentionPeriod: time.Minute,
		AdvisoryLockKey: scanorch.AuditPrunerLockKey,
		OnPrune:         func(c int64, _ time.Time) { atomic.StoreInt64(&pruneCount, c) },
		OnLockSkipped:   func(int64) { atomic.AddInt32(&skipped, 1) },
		OnError:         func(err error) { seenError = err },
	}
	pruner.Tick(context.Background())
	if seenError != nil {
		t.Fatalf("OnError fired: %v", seenError)
	}
	if atomic.LoadInt32(&skipped) != 0 {
		t.Errorf("OnLockSkipped fired = %d, want 0", skipped)
	}
	if atomic.LoadInt64(&pruneCount) != 42 {
		t.Errorf("OnPrune count = %d, want 42", pruneCount)
	}
}

// TestAuditPruner_OnTick_FiresOnEveryOutcome (v1.94+): the
// OnTick callback fires once per Tick regardless of outcome
// (success, error, or lock-skip). Duration is positive on all
// branches.
func TestAuditPruner_OnTick_FiresOnEveryOutcome(t *testing.T) {
	for _, tc := range []struct {
		name   string
		store  scanorch.ScheduleAuditStore
		lock   int64
		expect string
	}{
		{"happy", scanorch.NewMemoryScheduleAuditStore(), 0, "happy"},
		{"error", errAuditStore{}, 0, "error"},
		{"lock_skip", &fakeLockingAuditStore{acquired: false}, scanorch.AuditPrunerLockKey, "skip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fired int32
			var seenDuration time.Duration
			p := &scanorch.AuditPruner{
				AuditStore:      tc.store,
				RetentionPeriod: time.Minute,
				AdvisoryLockKey: tc.lock,
				OnTick: func(d time.Duration) {
					atomic.AddInt32(&fired, 1)
					seenDuration = d
				},
				// Other callbacks are no-ops to silence stderr.
				OnPrune:       func(int64, time.Time) {},
				OnError:       func(error) {},
				OnLockSkipped: func(int64) {},
			}
			p.Tick(context.Background())
			if atomic.LoadInt32(&fired) != 1 {
				t.Errorf("OnTick fired = %d, want 1", fired)
			}
			if seenDuration < 0 {
				t.Errorf("OnTick duration = %v, want >= 0", seenDuration)
			}
		})
	}
}

// fakeLockingAuditStore is a test-only ScheduleAuditStore that
// ALSO implements AdvisoryLockedAuditStore so the AuditPruner
// type-asserts into the locked path.
type fakeLockingAuditStore struct {
	acquired   bool
	pruneCount int64
	lockCalls  int
}

func (s *fakeLockingAuditStore) Append(context.Context, scanorch.ScheduleAuditEvent) (scanorch.ScheduleAuditEvent, error) {
	return scanorch.ScheduleAuditEvent{}, nil
}
func (s *fakeLockingAuditStore) ListBySchedule(context.Context, string) ([]scanorch.ScheduleAuditEvent, error) {
	return nil, nil
}
func (s *fakeLockingAuditStore) PruneOlderThan(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (s *fakeLockingAuditStore) PruneWithOverrides(context.Context, time.Time, map[string]time.Time) (int64, error) {
	return 0, nil
}
func (s *fakeLockingAuditStore) PruneWithLock(_ context.Context, _ int64, _ time.Time, _ map[string]time.Time) (int64, bool, error) {
	s.lockCalls++
	if !s.acquired {
		return 0, false, nil
	}
	return s.pruneCount, true, nil
}
