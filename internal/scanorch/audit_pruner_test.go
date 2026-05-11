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
