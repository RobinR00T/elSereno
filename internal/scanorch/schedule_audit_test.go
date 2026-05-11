package scanorch_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// TestMemoryScheduleAuditStore_Append_Happy: round-trip a
// force_overwrite event.
func TestMemoryScheduleAuditStore_Append_Happy(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	got, err := s.Append(context.Background(), scanorch.ScheduleAuditEvent{
		ScheduleID:    "abc",
		EventType:     scanorch.ScheduleAuditEventForceOverwrite,
		Operator:      "alice",
		PayloadBefore: json.RawMessage(`{"name":"before"}`),
		PayloadAfter:  json.RawMessage(`{"name":"after"}`),
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.ID == "" {
		t.Errorf("ID empty after Append")
	}
	if got.OccurredAt.IsZero() {
		t.Errorf("OccurredAt zero after Append")
	}
	if got.EventType != scanorch.ScheduleAuditEventForceOverwrite {
		t.Errorf("EventType = %q", got.EventType)
	}
}

// TestMemoryScheduleAuditStore_Append_InvalidEventType: bad
// event_type → ErrScheduleAuditInvalidEventType.
func TestMemoryScheduleAuditStore_Append_InvalidEventType(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	_, err := s.Append(context.Background(), scanorch.ScheduleAuditEvent{
		ScheduleID: "abc",
		EventType:  "garbage",
		Operator:   "alice",
	})
	if !errors.Is(err, scanorch.ErrScheduleAuditInvalidEventType) {
		t.Errorf("err = %v, want ErrScheduleAuditInvalidEventType", err)
	}
}

// TestMemoryScheduleAuditStore_ListBySchedule_NewestFirst:
// multiple events for one schedule come back sorted.
func TestMemoryScheduleAuditStore_ListBySchedule_NewestFirst(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	// Append three events for the same schedule.
	for i := 0; i < 3; i++ {
		_, err := s.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    "abc",
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("Append %d err = %v", i, err)
		}
	}
	got, err := s.ListBySchedule(context.Background(), "abc")
	if err != nil {
		t.Fatalf("List err = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// Newest first: idx 0 should be ≥ idx 1 ≥ idx 2.
	for i := 1; i < len(got); i++ {
		if got[i-1].OccurredAt.Before(got[i].OccurredAt) {
			t.Errorf("events not sorted DESC: idx %d %v < %v", i, got[i-1].OccurredAt, got[i].OccurredAt)
		}
	}
}

// TestMemoryScheduleAuditStore_ListBySchedule_FilterByID:
// events for other schedules are excluded.
func TestMemoryScheduleAuditStore_ListBySchedule_FilterByID(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	for _, sid := range []string{"abc", "def", "abc"} {
		_, _ = s.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    sid,
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
	}
	got, _ := s.ListBySchedule(context.Background(), "abc")
	if len(got) != 2 {
		t.Errorf("abc len = %d, want 2", len(got))
	}
	for _, e := range got {
		if e.ScheduleID != "abc" {
			t.Errorf("event for %q leaked into abc list", e.ScheduleID)
		}
	}
}

// TestMemoryScheduleAuditStore_ListBySchedule_Empty: no
// events for an unknown schedule → empty slice (not nil).
func TestMemoryScheduleAuditStore_ListBySchedule_Empty(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	got, err := s.ListBySchedule(context.Background(), "missing")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestMemoryScheduleAuditStore_PruneOlderThan_Happy (v1.86+):
// events with OccurredAt < cutoff are removed; newer ones stay.
func TestMemoryScheduleAuditStore_PruneOlderThan_Happy(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	// Append 5 events. Memory store stamps OccurredAt = now
	// on each Append — we sleep 1ms between calls to ensure
	// distinct timestamps (microsecond truncation otherwise
	// risks collisions on fast hardware).
	for i := 0; i < 5; i++ {
		_, err := s.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    "abc",
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("Append %d err = %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Capture the cutoff between event 2 and 3.
	all, _ := s.ListBySchedule(context.Background(), "abc")
	if len(all) != 5 {
		t.Fatalf("setup len = %d, want 5", len(all))
	}
	// ListBySchedule returns newest-first, so all[2] is the
	// middle event. Prune everything strictly before it.
	cutoff := all[2].OccurredAt
	removed, err := s.PruneOlderThan(context.Background(), cutoff)
	if err != nil {
		t.Fatalf("PruneOlderThan err = %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (events 0 and 1 in DESC order)", removed)
	}
	after, _ := s.ListBySchedule(context.Background(), "abc")
	if len(after) != 3 {
		t.Errorf("after-prune len = %d, want 3", len(after))
	}
}

// TestMemoryScheduleAuditStore_PruneOlderThan_FutureCutoff
// (v1.86+): cutoff in the future deletes every event. Used
// by the REST validator-warning to discourage operators
// from accidentally wiping the log, but the store accepts
// it (defence in depth).
func TestMemoryScheduleAuditStore_PruneOlderThan_FutureCutoff(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	for i := 0; i < 3; i++ {
		_, _ = s.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    "abc",
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
	}
	future := time.Now().Add(24 * time.Hour)
	removed, err := s.PruneOlderThan(context.Background(), future)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if removed != 3 {
		t.Errorf("removed = %d, want 3", removed)
	}
	after, _ := s.ListBySchedule(context.Background(), "abc")
	if len(after) != 0 {
		t.Errorf("after-prune len = %d, want 0", len(after))
	}
}

// TestMemoryScheduleAuditStore_PruneOlderThan_NoMatch
// (v1.86+): cutoff in the distant past removes nothing.
func TestMemoryScheduleAuditStore_PruneOlderThan_NoMatch(t *testing.T) {
	s := scanorch.NewMemoryScheduleAuditStore()
	for i := 0; i < 2; i++ {
		_, _ = s.Append(context.Background(), scanorch.ScheduleAuditEvent{
			ScheduleID:    "abc",
			EventType:     scanorch.ScheduleAuditEventForceOverwrite,
			Operator:      "alice",
			PayloadBefore: json.RawMessage(`{}`),
			PayloadAfter:  json.RawMessage(`{}`),
		})
	}
	past := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	removed, _ := s.PruneOlderThan(context.Background(), past)
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
	after, _ := s.ListBySchedule(context.Background(), "abc")
	if len(after) != 2 {
		t.Errorf("after-prune len = %d, want 2", len(after))
	}
}
