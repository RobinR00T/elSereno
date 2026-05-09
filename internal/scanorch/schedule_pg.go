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
const scheduleColumns = `
id, name, template_input, template_plugins, template_default_port,
interval_seconds, cron_expr, enabled, operator, created_at, last_fired_at`

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
   interval_seconds, cron_expr, enabled, operator, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $9)`
	if _, err := s.q.Exec(ctx, sql,
		sched.ID, sched.Name, sched.Template.Input, plugins, sched.Template.DefaultPort,
		sched.IntervalSeconds, sched.CronExpr, operator, sched.CreatedAt,
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
		&s.IntervalSeconds, &s.CronExpr, &s.Enabled, &s.Operator,
		&s.CreatedAt, &lastFiredAt,
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
