package scanorch

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// ScheduleAuditEventType (v1.84+) enumerates the events the
// audit log persists. v1.84 introduced "force_overwrite".
// v1.88 expands to "delete" + "set_enabled_true" +
// "set_enabled_false" so the audit captures the full
// lifecycle of operator-driven mutations.
//
// The SQL DDL is the source of truth (PITF-030); this Go
// enum mirrors the CHECK constraint in migration 00012.
type ScheduleAuditEventType string

// Event type constants. See package doc.
const (
	// ScheduleAuditEventForceOverwrite (v1.84+): operator
	// submitted a PUT without If-Match — overriding the
	// v1.78 optimistic-locking precondition.
	ScheduleAuditEventForceOverwrite ScheduleAuditEventType = "force_overwrite"
	// ScheduleAuditEventDelete (v1.88+): schedule was
	// removed via DELETE /api/v1/schedules/{id}. The
	// payload_before snapshot captures the schedule state
	// at deletion time; payload_after is JSON null.
	// schedule_id may be NULL on read because the FK SET
	// NULL fires when the schedule row is deleted.
	ScheduleAuditEventDelete ScheduleAuditEventType = "delete"
	// ScheduleAuditEventSetEnabledTrue (v1.88+): schedule
	// was enabled via POST /api/v1/schedules/{id}/enable.
	ScheduleAuditEventSetEnabledTrue ScheduleAuditEventType = "set_enabled_true"
	// ScheduleAuditEventSetEnabledFalse (v1.88+): schedule
	// was disabled via POST /api/v1/schedules/{id}/disable.
	ScheduleAuditEventSetEnabledFalse ScheduleAuditEventType = "set_enabled_false"
)

// ValidScheduleAuditEventTypes is the canonical set, used by
// validation + as the source of truth for the SQL CHECK.
var ValidScheduleAuditEventTypes = []ScheduleAuditEventType{
	ScheduleAuditEventForceOverwrite,
	ScheduleAuditEventDelete,
	ScheduleAuditEventSetEnabledTrue,
	ScheduleAuditEventSetEnabledFalse,
}

// ScheduleAuditEvent (v1.84+) is one row of the audit log
// for a schedule. PayloadBefore + PayloadAfter are full
// JSON snapshots of the ScanSchedule at the moment of the
// event — operators get the literal field-by-field
// before/after so they can audit what was changed.
type ScheduleAuditEvent struct {
	// ID is a 16-char hex identifier generated on Append.
	ID string `json:"id"`
	// ScheduleID is the schedule the event applies to.
	ScheduleID string `json:"schedule_id"`
	// EventType is one of ValidScheduleAuditEventTypes.
	EventType ScheduleAuditEventType `json:"event_type"`
	// Operator is the identity that triggered the event
	// (X-Operator header or "anonymous" fallback).
	Operator string `json:"operator"`
	// OccurredAt is the timestamp the event was recorded.
	OccurredAt time.Time `json:"occurred_at"`
	// PayloadBefore is the pre-update JSON snapshot. May be
	// json.RawMessage("null") if the event captures a
	// brand-new creation (not currently used).
	PayloadBefore json.RawMessage `json:"payload_before"`
	// PayloadAfter is the post-update JSON snapshot.
	PayloadAfter json.RawMessage `json:"payload_after"`
}

// ErrScheduleAuditInvalidEventType (v1.84+) means Append
// was called with an event_type that's not in
// ValidScheduleAuditEventTypes. Defence in depth — the SQL
// CHECK constraint is the wire-level guard.
var ErrScheduleAuditInvalidEventType = errors.New("scanorch: schedule audit invalid event_type")

// ScheduleAuditStore (v1.84+) is the persistence interface
// for the schedule audit log. v1.84 ships both a memory
// implementation (for tests + memory-mode deployments) and
// a Postgres-backed one (matching scan_schedule_audit in
// migration 00011).
type ScheduleAuditStore interface {
	// Append records a new audit event. The store generates
	// ID + OccurredAt; everything else comes from the caller.
	// Returns the persisted event so the caller can include
	// it in REST responses.
	Append(ctx context.Context, event ScheduleAuditEvent) (ScheduleAuditEvent, error)
	// ListBySchedule returns all audit events for the
	// schedule, sorted by OccurredAt DESC (newest first).
	// Empty slice when the schedule has never been audited.
	ListBySchedule(ctx context.Context, scheduleID string) ([]ScheduleAuditEvent, error)
	// PruneOlderThan (v1.86+) removes events with
	// OccurredAt < cutoff. Returns the number of deleted
	// rows. Used for retention-policy enforcement — operator
	// invokes via DELETE /api/v1/schedules/audit?before=…
	// or (future) a scheduled background pruner.
	//
	// Cutoff times in the future are valid and delete every
	// event — defensive callers should reject obviously-
	// wrong cutoffs at the REST layer.
	PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	// PruneWithOverrides (v1.89+) is the per-schedule-aware
	// variant of PruneOlderThan. globalCutoff applies to
	// events whose schedule_id is NOT in `overrides`; for
	// each (schedule_id → schedule-specific cutoff) entry in
	// `overrides`, those events are pruned with the per-
	// schedule cutoff instead.
	//
	// Semantics for orphaned audit rows (schedule_id IS NULL —
	// happens when v1.88 FK SET NULL fires on schedule delete):
	// they always fall under the globalCutoff. The override
	// table is keyed by the live schedule_id, which is gone
	// for deleted rows.
	//
	// nil/empty overrides → equivalent to PruneOlderThan.
	// Returns the total number of rows deleted across both
	// the global + override passes.
	PruneWithOverrides(ctx context.Context, globalCutoff time.Time, overrides map[string]time.Time) (int64, error)
}

// MemoryScheduleAuditStore is an in-memory ScheduleAuditStore
// for tests + memory-mode deployments. Concurrency-safe.
type MemoryScheduleAuditStore struct {
	mu     sync.RWMutex
	events []ScheduleAuditEvent
}

// NewMemoryScheduleAuditStore returns an empty store.
func NewMemoryScheduleAuditStore() *MemoryScheduleAuditStore {
	return &MemoryScheduleAuditStore{}
}

// Append validates the event_type + stamps ID/OccurredAt +
// persists. Returns the persisted event.
func (s *MemoryScheduleAuditStore) Append(_ context.Context, event ScheduleAuditEvent) (ScheduleAuditEvent, error) {
	if !isValidScheduleAuditEventType(event.EventType) {
		return ScheduleAuditEvent{}, ErrScheduleAuditInvalidEventType
	}
	id, err := generateID()
	if err != nil {
		return ScheduleAuditEvent{}, err
	}
	event.ID = id
	event.OccurredAt = time.Now().UTC().Truncate(time.Microsecond)
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
	return event, nil
}

// PruneOlderThan (v1.86+) removes events with OccurredAt
// before the cutoff. Returns the number of removed rows.
func (s *MemoryScheduleAuditStore) PruneOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]ScheduleAuditEvent, 0, len(s.events))
	var removed int64
	for _, e := range s.events {
		if e.OccurredAt.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
	return removed, nil
}

// PruneWithOverrides (v1.89+) applies per-schedule cutoffs +
// a global fallback. See the interface doc for semantics.
func (s *MemoryScheduleAuditStore) PruneWithOverrides(_ context.Context, globalCutoff time.Time, overrides map[string]time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := make([]ScheduleAuditEvent, 0, len(s.events))
	var removed int64
	for _, e := range s.events {
		cutoff := globalCutoff
		if overrides != nil {
			if c, ok := overrides[e.ScheduleID]; ok {
				cutoff = c
			}
		}
		if e.OccurredAt.Before(cutoff) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	s.events = kept
	return removed, nil
}

// ListBySchedule filters by schedule_id + sorts by
// OccurredAt DESC.
func (s *MemoryScheduleAuditStore) ListBySchedule(_ context.Context, scheduleID string) ([]ScheduleAuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScheduleAuditEvent, 0)
	for _, e := range s.events {
		if e.ScheduleID == scheduleID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OccurredAt.After(out[j].OccurredAt)
	})
	return out, nil
}

// isValidScheduleAuditEventType checks the type against
// ValidScheduleAuditEventTypes.
func isValidScheduleAuditEventType(t ScheduleAuditEventType) bool {
	for _, v := range ValidScheduleAuditEventTypes {
		if v == t {
			return true
		}
	}
	return false
}

// Compile-time guard.
var _ ScheduleAuditStore = (*MemoryScheduleAuditStore)(nil)
