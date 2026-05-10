package scanorch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DBScheduleStore is the postgres-backed ScheduleStore. v1.71+.
// Schema in migration 00007_scan_schedules.sql.
//
// All mutations use single-statement SQL (INSERT / UPDATE /
// DELETE) — no multi-row transactions. The Scheduler tick is
// the only writer that races against operator-driven CRUD,
// and its MarkFired update is a single UPDATE that's atomic
// at the row level. SELECT FOR UPDATE on the schedule row
// before MarkFired would be required if multiple `serve`
// instances share the same DB; deferred — the typical
// deployment is a single serve process.
type DBScheduleStore struct {
	q Querier
}

// NewDBScheduleStore wraps the supplied Querier.
func NewDBScheduleStore(q Querier) *DBScheduleStore { return &DBScheduleStore{q: q} }

// scheduleColumns is the column list returned by every Get /
// List query. Single source of truth for the SELECT projection
// + the rowScanner.
//
// v1.73+: includes cron_expr.
// v1.75+: includes timezone.
// v1.78+: includes updated_at.
const scheduleColumns = `
id, name, template_input, template_plugins, template_default_port,
interval_seconds, cron_expr, timezone, enabled, operator, created_at, updated_at, last_fired_at`

// Create inserts a new schedule. Validation + cadence
// resolution shares buildScheduleFromRequest with
// MemoryScheduleStore so the rules are a single source of
// truth (including the v1.73+ cron_expr alternative).
func (s *DBScheduleStore) Create(ctx context.Context, req CreateScheduleRequest, operator string) (ScanSchedule, error) {
	sched, err := buildScheduleFromRequest(req, operator)
	if err != nil {
		return ScanSchedule{}, err
	}
	plugins := sched.Template.Plugins
	if plugins == nil {
		plugins = []string{}
	}
	const sql = `
INSERT INTO scan_schedules
  (id, name, template_input, template_plugins, template_default_port,
   interval_seconds, cron_expr, timezone, enabled, operator, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9, $10, $11)`
	if _, err := s.q.Exec(ctx, sql,
		sched.ID, sched.Name, sched.Template.Input, plugins, sched.Template.DefaultPort,
		sched.IntervalSeconds, sched.CronExpr, sched.Timezone, operator, sched.CreatedAt, sched.UpdatedAt,
	); err != nil {
		return ScanSchedule{}, fmt.Errorf("scanorch: insert schedule: %w", err)
	}
	// Defensive copy of plugins for the returned struct so the
	// caller's mutation can't alias into the persisted row.
	sched.Template.Plugins = append([]string(nil), plugins...)
	return sched, nil
}

// Get returns the schedule by ID.
func (s *DBScheduleStore) Get(ctx context.Context, id string) (ScanSchedule, error) {
	rows, err := s.q.Query(ctx, "SELECT "+scheduleColumns+" FROM scan_schedules WHERE id = $1", id)
	if err != nil {
		return ScanSchedule{}, fmt.Errorf("scanorch: query schedule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return ScanSchedule{}, ErrScheduleNotFound
	}
	return scanSchedule(rows)
}

// List returns every schedule sorted by name.
func (s *DBScheduleStore) List(ctx context.Context) ([]ScanSchedule, error) {
	rows, err := s.q.Query(ctx,
		"SELECT "+scheduleColumns+" FROM scan_schedules ORDER BY name ASC")
	if err != nil {
		return nil, fmt.Errorf("scanorch: list schedules: %w", err)
	}
	defer rows.Close()
	var out []ScanSchedule
	for rows.Next() {
		sched, scanErr := scanSchedule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, sched)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanorch: list schedules (rows): %w", err)
	}
	return out, nil
}

// Update replaces the editable fields of an existing schedule.
// Single-statement UPDATE ... RETURNING so the response
// reflects the persisted row (last_fired_at + created_at +
// operator + enabled survive untouched).
//
// The DB-level CHECK XOR (introduced in migration 00008)
// catches any cadence violation that slipped past the Go-side
// validation; the parameterised UPDATE binds both columns so
// the constraint sees both values atomically.
//
// v1.78+: req.IfMatch is the optimistic-locking precondition.
// When non-nil, the WHERE clause adds `AND updated_at = $9`,
// so a 0-row response means EITHER the schedule doesn't exist
// OR another operator updated it since the caller last read.
// We disambiguate by issuing a follow-up SELECT — costs an
// extra round-trip only on the precondition-failure path
// (rare). updated_at is also written ($10) so the new value
// is observable on the next read.
func (s *DBScheduleStore) Update(ctx context.Context, id string, req UpdateScheduleRequest) (ScanSchedule, error) {
	if err := validateScheduleFields(req.Name, req.Template, req.IntervalSeconds, req.CronExpr, req.Timezone); err != nil {
		return ScanSchedule{}, err
	}
	plugins := req.Template.Plugins
	if plugins == nil {
		plugins = []string{}
	}
	// Stage the cadence on a temporary ScanSchedule so we
	// reuse applyCadence's "reset both, set one" logic.
	var staged ScanSchedule
	applyCadence(&staged, req.IntervalSeconds, req.CronExpr)
	now := time.Now().UTC().Truncate(time.Microsecond)
	var (
		rows pgx.Rows
		err  error
	)
	if req.IfMatch != nil {
		const sqlIfMatch = `
UPDATE scan_schedules
SET name = $2, template_input = $3, template_plugins = $4,
    template_default_port = $5, interval_seconds = $6, cron_expr = $7,
    timezone = $8, updated_at = $10
WHERE id = $1 AND updated_at = $9
RETURNING ` + scheduleColumns
		rows, err = s.q.Query(ctx, sqlIfMatch,
			id, req.Name, req.Template.Input, plugins, req.Template.DefaultPort,
			staged.IntervalSeconds, staged.CronExpr, req.Timezone, *req.IfMatch, now,
		)
	} else {
		const sqlNoMatch = `
UPDATE scan_schedules
SET name = $2, template_input = $3, template_plugins = $4,
    template_default_port = $5, interval_seconds = $6, cron_expr = $7,
    timezone = $8, updated_at = $9
WHERE id = $1
RETURNING ` + scheduleColumns
		rows, err = s.q.Query(ctx, sqlNoMatch,
			id, req.Name, req.Template.Input, plugins, req.Template.DefaultPort,
			staged.IntervalSeconds, staged.CronExpr, req.Timezone, now,
		)
	}
	if err != nil {
		return ScanSchedule{}, fmt.Errorf("scanorch: update schedule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		// 0-row UPDATE. Disambiguate not-found vs.
		// precondition-failure when IfMatch is set.
		if req.IfMatch == nil {
			return ScanSchedule{}, ErrScheduleNotFound
		}
		rows.Close()
		exists, existsErr := s.scheduleExists(ctx, id)
		if existsErr != nil {
			return ScanSchedule{}, existsErr
		}
		if !exists {
			return ScanSchedule{}, ErrScheduleNotFound
		}
		return ScanSchedule{}, ErrSchedulePreconditionFailed
	}
	return scanSchedule(rows)
}

// scheduleExists is a small helper used to disambiguate
// not-found vs. precondition-failure on Update. Returns nil
// error + false if the row is missing.
func (s *DBScheduleStore) scheduleExists(ctx context.Context, id string) (bool, error) {
	rows, err := s.q.Query(ctx, "SELECT 1 FROM scan_schedules WHERE id = $1", id)
	if err != nil {
		return false, fmt.Errorf("scanorch: schedule exists check: %w", err)
	}
	defer rows.Close()
	return rows.Next(), nil
}

// Delete removes the schedule.
func (s *DBScheduleStore) Delete(ctx context.Context, id string) error {
	tag, err := s.q.Exec(ctx, "DELETE FROM scan_schedules WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("scanorch: delete schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return nil
}

// MarkFired stamps last_fired_at.
func (s *DBScheduleStore) MarkFired(ctx context.Context, id string, now time.Time) error {
	tag, err := s.q.Exec(ctx,
		"UPDATE scan_schedules SET last_fired_at = $2 WHERE id = $1",
		id, now.UTC().Truncate(time.Microsecond))
	if err != nil {
		return fmt.Errorf("scanorch: mark schedule fired: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return nil
}

// SetEnabled toggles the kill-switch.
func (s *DBScheduleStore) SetEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := s.q.Exec(ctx,
		"UPDATE scan_schedules SET enabled = $2 WHERE id = $1",
		id, enabled)
	if err != nil {
		return fmt.Errorf("scanorch: set schedule enabled: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrScheduleNotFound
	}
	return nil
}

// scanSchedule decodes a row into a ScanSchedule.
//
// v1.73+: cron_expr column joins the projection. The mutually-
// exclusive XOR check at the SQL level guarantees exactly one
// of interval_seconds (>= 60) or cron_expr (non-empty) is set,
// so the Go-side IsDue routes correctly without re-validating.
func scanSchedule(rows pgx.Rows) (ScanSchedule, error) {
	var (
		s                 ScanSchedule
		templateInput     string
		templatePlugins   []string
		templateDefaultPt int
		lastFiredAt       *time.Time
	)
	if err := rows.Scan(
		&s.ID, &s.Name,
		&templateInput, &templatePlugins, &templateDefaultPt,
		&s.IntervalSeconds, &s.CronExpr, &s.Timezone, &s.Enabled, &s.Operator,
		&s.CreatedAt, &s.UpdatedAt, &lastFiredAt,
	); err != nil {
		return ScanSchedule{}, fmt.Errorf("scanorch: scan schedule: %w", err)
	}
	s.Template = SubmitRequest{
		Input:       templateInput,
		Plugins:     templatePlugins,
		DefaultPort: templateDefaultPt,
	}
	if lastFiredAt != nil {
		s.LastFiredAt = *lastFiredAt
	}
	return s, nil
}

// Compile-time guard.
var _ ScheduleStore = (*DBScheduleStore)(nil)

// silence unused-import warning when build tags strip Querier
// usage paths.
var _ = errors.New
