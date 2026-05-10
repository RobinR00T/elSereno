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
// audit log persists. Currently only "force_overwrite"
// (operator submitted a PUT without If-Match — possibly via
// the dashboard's Force-overwrite button — overriding the
// v1.78 optimistic-locking precondition). Future cycles may
// add "delete", "set_enabled", etc. The Go enum stays the
// source of truth; SQL CHECK constraint mirrors it.
type ScheduleAuditEventType string

// Event type constants. See package doc.
const (
	ScheduleAuditEventForceOverwrite ScheduleAuditEventType = "force_overwrite"
)

// ValidScheduleAuditEventTypes is the canonical set, used by
// validation + as the source of truth for the SQL CHECK.
var ValidScheduleAuditEventTypes = []ScheduleAuditEventType{
	ScheduleAuditEventForceOverwrite,
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
