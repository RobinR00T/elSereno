package scanorch

import (
	"context"
	"fmt"
	"time"
)

// DBScheduleAuditStore is the Postgres-backed
// ScheduleAuditStore. v1.84+. Schema lives in migration
// 00011_scan_schedule_audit.sql. The CHECK constraint on
// event_type mirrors ValidScheduleAuditEventTypes (defence
// in depth — both Go-side validation + SQL CHECK reject
// invalid values).
type DBScheduleAuditStore struct {
	q Querier
}

// NewDBScheduleAuditStore wraps the supplied Querier.
func NewDBScheduleAuditStore(q Querier) *DBScheduleAuditStore { return &DBScheduleAuditStore{q: q} }

// scheduleAuditColumns is the SELECT projection used by
// every read query. Source of truth for the rowScanner.
const scheduleAuditColumns = `
id, schedule_id, event_type, operator, occurred_at,
payload_before, payload_after`

// Append validates + INSERTs the event. Returns the
// persisted row so the caller can surface ID + OccurredAt.
func (s *DBScheduleAuditStore) Append(ctx context.Context, event ScheduleAuditEvent) (ScheduleAuditEvent, error) {
	if !isValidScheduleAuditEventType(event.EventType) {
		return ScheduleAuditEvent{}, ErrScheduleAuditInvalidEventType
	}
	if event.ID == "" {
		id, err := generateID()
		if err != nil {
			return ScheduleAuditEvent{}, err
		}
		event.ID = id
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = nowUTCMicro()
	}
	const sql = `
INSERT INTO scan_schedule_audit
  (id, schedule_id, event_type, operator, occurred_at,
   payload_before, payload_after)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if _, err := s.q.Exec(ctx, sql,
		event.ID, event.ScheduleID, string(event.EventType),
		event.Operator, event.OccurredAt,
		[]byte(event.PayloadBefore), []byte(event.PayloadAfter),
	); err != nil {
		return ScheduleAuditEvent{}, fmt.Errorf("scanorch: insert schedule audit: %w", err)
	}
	return event, nil
}

// PruneOlderThan (v1.86+) removes rows with occurred_at <
// cutoff. Returns the row count from the DELETE command tag.
func (s *DBScheduleAuditStore) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.q.Exec(ctx,
		"DELETE FROM scan_schedule_audit WHERE occurred_at < $1",
		cutoff.UTC())
	if err != nil {
		return 0, fmt.Errorf("scanorch: prune schedule audit: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PruneWithOverrides (v1.89+) prunes in two passes:
//
//  1. Per-schedule pass: for each (id → cutoff) in `overrides`,
//     DELETE WHERE schedule_id = id AND occurred_at < cutoff.
//
//  2. Global pass: DELETE WHERE
//     (schedule_id IS NULL OR schedule_id NOT IN keys(overrides))
//     AND occurred_at < globalCutoff.
//
// Two passes (not one big CASE expression) keep each statement
// simple + give clearer command tags. Total row count is
// summed.
//
// Empty/nil overrides → falls back to PruneOlderThan
// semantics (one global pass).
func (s *DBScheduleAuditStore) PruneWithOverrides(ctx context.Context, globalCutoff time.Time, overrides map[string]time.Time) (int64, error) {
	if len(overrides) == 0 {
		return s.PruneOlderThan(ctx, globalCutoff)
	}
	var total int64
	// Pass 1: per-schedule. Iterate the map deterministically
	// for stable error messages if a Exec fails mid-loop.
	ids := make([]string, 0, len(overrides))
	for id := range overrides {
		ids = append(ids, id)
	}
	sortStrings(ids)
	for _, id := range ids {
		cutoff := overrides[id]
		tag, err := s.q.Exec(ctx,
			"DELETE FROM scan_schedule_audit WHERE schedule_id = $1 AND occurred_at < $2",
			id, cutoff.UTC())
		if err != nil {
			return total, fmt.Errorf("scanorch: prune schedule audit (override %s): %w", id, err)
		}
		total += tag.RowsAffected()
	}
	// Pass 2: global cutoff for everything NOT in the overrides
	// map. NULL schedule_id (v1.88 tombstoned rows) belongs in
	// this pass.
	tag, err := s.q.Exec(ctx,
		"DELETE FROM scan_schedule_audit"+
			" WHERE (schedule_id IS NULL OR schedule_id <> ALL($1))"+
			" AND occurred_at < $2",
		ids, globalCutoff.UTC())
	if err != nil {
		return total, fmt.Errorf("scanorch: prune schedule audit (global): %w", err)
	}
	total += tag.RowsAffected()
	return total, nil
}

// sortStrings is a tiny string-slice sort (avoid pulling in the
// sort package for one call site). N is the number of schedules
// with retention overrides — typically <50, often <10.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		v := s[i]
		j := i - 1
		for j >= 0 && s[j] > v {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = v
	}
}

// ListBySchedule returns the events for a schedule, newest
// first.
func (s *DBScheduleAuditStore) ListBySchedule(ctx context.Context, scheduleID string) ([]ScheduleAuditEvent, error) {
	rows, err := s.q.Query(ctx,
		"SELECT "+scheduleAuditColumns+
			" FROM scan_schedule_audit"+
			" WHERE schedule_id = $1"+
			" ORDER BY occurred_at DESC",
		scheduleID)
	if err != nil {
		return nil, fmt.Errorf("scanorch: list schedule audit: %w", err)
	}
	defer rows.Close()
	out := make([]ScheduleAuditEvent, 0)
	for rows.Next() {
		var (
			e             ScheduleAuditEvent
			eventTypeStr  string
			payloadBefore []byte
			payloadAfter  []byte
		)
		if err := rows.Scan(
			&e.ID, &e.ScheduleID, &eventTypeStr, &e.Operator, &e.OccurredAt,
			&payloadBefore, &payloadAfter,
		); err != nil {
			return nil, fmt.Errorf("scanorch: scan schedule audit: %w", err)
		}
		e.EventType = ScheduleAuditEventType(eventTypeStr)
		e.PayloadBefore = payloadBefore
		e.PayloadAfter = payloadAfter
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanorch: list schedule audit (rows): %w", err)
	}
	return out, nil
}

// nowUTCMicro is a tiny helper for stamping OccurredAt at
// microsecond precision (matching the TIMESTAMPTZ resolution
// the Postgres column persists).
func nowUTCMicro() time.Time {
	return time.Now().UTC().Truncate(time.Microsecond)
}

// Compile-time guard.
var _ ScheduleAuditStore = (*DBScheduleAuditStore)(nil)
