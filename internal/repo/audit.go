package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEntry is the dashboard-facing projection of a row in
// `audit_log`. The on-disk shape is identical to
// `internal/audit.Entry`, but the JSON tags here are the ones
// the dashboard's JS expects (snake_case) + we omit the
// chain-integrity columns (prev_hash / entry_hash) that the
// dashboard never displays — they live in the audit chain
// proper for offline `audit verify-file`.
//
// v1.19 chunk 1.
type AuditEntry struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurred_at"`
	Actor      string          `json:"actor"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	// Tombstoned mirrors the `payload_tombstoned` flag the
	// audit purge sets when a payload has been redacted (see
	// ADR-013). The JSON-rendered payload is `null` for
	// tombstoned rows; consumers can hide such rows or render
	// them as "[redacted]". The chain entry itself stays.
	Tombstoned bool `json:"tombstoned,omitempty"`
}

const auditDefaultLimit = 50
const auditMaxLimit = 500

// AuditQuery filters ListAuditLog. Zero values → newest 50.
type AuditQuery struct {
	// EventType, if non-empty, restricts to one event_type.
	// Validated against the SQL CHECK enum at scan time.
	EventType string
	// Actor, if non-empty, restricts to a single actor (e.g.
	// `system`, `operator`, a vault-derived UUID).
	Actor string
	// OccurredAfter filters occurred_at > T for cursor
	// pagination (pair with the oldest returned row's
	// OccurredAt to walk backward in time).
	OccurredAfter time.Time
	// Limit clamped to [1, auditMaxLimit]; default
	// auditDefaultLimit.
	Limit int
}

// ListAuditLog returns the newest audit entries matching q in
// descending occurred_at order. Tombstoned rows are returned
// with their `payload` rendered as `null`; the `tombstoned`
// flag flips so the dashboard can render them differently.
//
// v1.19 chunk 1: backs `GET /api/v1/audit` for the dashboard's
// audit-feed panel.
func ListAuditLog(ctx context.Context, q Querier, aq AuditQuery) ([]AuditEntry, error) {
	limit := aq.Limit
	if limit <= 0 {
		limit = auditDefaultLimit
	}
	if limit > auditMaxLimit {
		limit = auditMaxLimit
	}
	var (
		filters []string
		args    []any
	)
	if aq.EventType != "" {
		args = append(args, aq.EventType)
		filters = append(filters, fmt.Sprintf("event_type = $%d", len(args)))
	}
	if aq.Actor != "" {
		args = append(args, aq.Actor)
		filters = append(filters, fmt.Sprintf("actor = $%d", len(args)))
	}
	if !aq.OccurredAfter.IsZero() {
		args = append(args, aq.OccurredAfter)
		filters = append(filters, fmt.Sprintf("occurred_at > $%d", len(args)))
	}
	where := ""
	if len(filters) > 0 {
		where = "WHERE " + joinAnd(filters)
	}
	args = append(args, limit)
	sql := fmt.Sprintf(`
		SELECT id, occurred_at, actor, event_type,
		       CASE WHEN payload_tombstoned THEN 'null'::jsonb ELSE payload END,
		       payload_tombstoned
		FROM audit_log
		%s
		ORDER BY occurred_at DESC
		LIMIT $%d`, where, len(args))
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: list audit_log: %w", err)
	}
	defer rows.Close()
	out := make([]AuditEntry, 0, limit)
	for rows.Next() {
		var e AuditEntry
		var payload []byte
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Actor, &e.EventType, &payload, &e.Tombstoned); err != nil {
			return nil, fmt.Errorf("repo: scan audit_log: %w", err)
		}
		e.Payload = payload
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditCadence is a per-(event_type, day) row used by the
// reload-cadence summary panel (v1.19 chunk 2). Day is
// truncated to UTC midnight; Count is the total rows for that
// (event_type, day) cell.
type AuditCadence struct {
	Day       time.Time `json:"day"`
	EventType string    `json:"event_type"`
	Count     int       `json:"count"`
}

// ListAuditCadence returns per-day per-event-type counts for
// the last `days` days. Used by v1.19 chunk 2's reload-cadence
// panel; generic enough that future "events over time" charts
// can reuse it. days is clamped to [1, 90].
func ListAuditCadence(ctx context.Context, q Querier, eventType string, days int) ([]AuditCadence, error) {
	if days <= 0 {
		days = 7
	}
	if days > 90 {
		days = 90
	}
	args := []any{days}
	where := fmt.Sprintf("WHERE occurred_at >= NOW() - ($%d || ' days')::interval", len(args))
	if eventType != "" {
		args = append(args, eventType)
		where += fmt.Sprintf(" AND event_type = $%d", len(args))
	}
	sql := fmt.Sprintf(`
		SELECT date_trunc('day', occurred_at AT TIME ZONE 'UTC') AS day,
		       event_type,
		       COUNT(*)::bigint AS n
		FROM audit_log
		%s
		GROUP BY day, event_type
		ORDER BY day DESC, event_type ASC`, where)
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: audit cadence: %w", err)
	}
	defer rows.Close()
	out := []AuditCadence{}
	for rows.Next() {
		var c AuditCadence
		var n int64
		if err := rows.Scan(&c.Day, &c.EventType, &n); err != nil {
			return nil, fmt.Errorf("repo: scan audit cadence: %w", err)
		}
		c.Count = int(n)
		out = append(out, c)
	}
	return out, rows.Err()
}
