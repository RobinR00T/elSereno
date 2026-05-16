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
// v1.89+: includes audit_retention_days (NULL-able).
// v2.4+: includes tags (TEXT[], DEFAULT empty array).
// v2.10+: includes source_schedule_id (NULL-able TEXT FK).
const scheduleColumns = `
id, name, template_input, template_plugins, template_default_port,
interval_seconds, cron_expr, timezone, enabled, operator, created_at, updated_at, last_fired_at,
audit_retention_days, tags, source_schedule_id`

// Create inserts a new schedule. Validation + cadence
// resolution shares buildScheduleFromRequest with
// MemoryScheduleStore so the rules are a single source of
// truth (including the v1.73+ cron_expr alternative).
//
// v2.10+: thin wrapper over CreateClone with empty sourceID.
func (s *DBScheduleStore) Create(ctx context.Context, req CreateScheduleRequest, operator string) (ScanSchedule, error) {
	return s.CreateClone(ctx, req, operator, "")
}

// CreateClone (v2.10+) is Create + stamps source_schedule_id.
// Empty sourceID stores NULL (operator-created, not a clone).
func (s *DBScheduleStore) CreateClone(ctx context.Context, req CreateScheduleRequest, operator, sourceID string) (ScanSchedule, error) {
	sched, err := buildScheduleFromRequest(req, operator)
	if err != nil {
		return ScanSchedule{}, err
	}
	plugins := sched.Template.Plugins
	if plugins == nil {
		plugins = []string{}
	}
	tags := sched.Tags
	if tags == nil {
		tags = []string{} // postgres ARRAY can't take nil.
	}
	const sql = `
INSERT INTO scan_schedules
  (id, name, template_input, template_plugins, template_default_port,
   interval_seconds, cron_expr, timezone, enabled, operator, created_at, updated_at,
   audit_retention_days, tags, source_schedule_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9, $10, $11, $12, $13, $14)`
	if _, err := s.q.Exec(ctx, sql,
		sched.ID, sched.Name, sched.Template.Input, plugins, sched.Template.DefaultPort,
		sched.IntervalSeconds, sched.CronExpr, sched.Timezone, operator, sched.CreatedAt, sched.UpdatedAt,
		auditRetentionDaysToDB(sched.AuditRetentionDays), tags, nullableString(sourceID),
	); err != nil {
		return ScanSchedule{}, fmt.Errorf("scanorch: insert schedule: %w", err)
	}
	// Defensive copy of plugins for the returned struct so the
	// caller's mutation can't alias into the persisted row.
	sched.Template.Plugins = append([]string(nil), plugins...)
	sched.SourceScheduleID = sourceID
	return sched, nil
}

// WithTx (v2.20 interface; v2.21 implementation) executes fn
// within a single PG transaction. Type-asserts the Querier to
// the txQuerier interface (BeginTx); falls back to pass-through
// if the Querier doesn't support transactions (unit-test
// fakes).
//
// Semantics:
//   - fn returns nil → Commit.
//   - fn returns non-nil → Rollback + return that error.
//   - BeginTx error → returned verbatim (no fn invocation).
//   - Commit error → returned verbatim (changes lost; rare).
//
// The tx-scoped DBScheduleStore handed to fn shares the same
// schema accessors but bound to the pgx.Tx so all CRUD inside
// fn participates in the tx.
func (s *DBScheduleStore) WithTx(ctx context.Context, fn func(ScheduleStore) error) error {
	beginner, ok := s.q.(txQuerier)
	if !ok {
		// Test-fake fallback — no real BeginTx; document
		// matches MemoryScheduleStore.
		return fn(s)
	}
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("scanorch: schedule begin tx: %w", err)
	}
	txStore := &DBScheduleStore{q: tx}
	if fnErr := fn(txStore); fnErr != nil {
		_ = tx.Rollback(ctx) // best-effort
		return fnErr
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("scanorch: schedule commit tx: %w", err)
	}
	return nil
}

// RenameTag (v2.16+) atomic SQL replace + canonicalise.
// ARRAY_REPLACE swaps every `from` → `to`; the unnest +
// array_agg DISTINCT ORDER BY pass dedupes + re-sorts the
// resulting array so the canonical invariant survives.
func (s *DBScheduleStore) RenameTag(ctx context.Context, from, to string) (int64, error) {
	if from == "" || to == "" {
		return 0, ErrTagRenameRequiresBoth
	}
	if from == to {
		return 0, ErrTagRenameNoOp
	}
	if _, err := canonicaliseTags([]string{from}); err != nil {
		return 0, err
	}
	if _, err := canonicaliseTags([]string{to}); err != nil {
		return 0, err
	}
	// Bump updated_at so v1.78 optimistic-locking clients
	// pick up the change. Single UPDATE → tx-atomic per row;
	// across-rows the operation is "best-effort consistent"
	// (a concurrent reader between rows may see a half-
	// renamed fleet for a few ms).
	const sql = `
UPDATE scan_schedules
SET tags = (
  SELECT COALESCE(array_agg(DISTINCT t ORDER BY t), ARRAY[]::text[])
  FROM unnest(ARRAY_REPLACE(tags, $1, $2)) AS t
),
    updated_at = NOW()
WHERE $1 = ANY(tags)`
	tag, err := s.q.Exec(ctx, sql, from, to)
	if err != nil {
		return 0, fmt.Errorf("scanorch: rename tag: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListClonesOf (v2.10+) uses the partial index from
// migration 00017 for fast clone-provenance lookups.
//
// v2.23+: thin wrapper over ListClonesOfDeep with depth=1.
func (s *DBScheduleStore) ListClonesOf(ctx context.Context, sourceID string) ([]ScanSchedule, error) {
	return s.ListClonesOfDeep(ctx, sourceID, 1)
}

// ListClonesOfDeep (v2.23+) walks the clone chain via a
// recursive CTE. Each row carries its BFS depth via the
// `clone_depth` projection alias.
func (s *DBScheduleStore) ListClonesOfDeep(ctx context.Context, sourceID string, depth int) ([]ScanSchedule, error) {
	if sourceID == "" {
		return nil, nil
	}
	if depth < CloneDepthMin {
		depth = CloneDepthMin
	}
	if depth > CloneDepthMax {
		depth = CloneDepthMax
	}
	// Recursive CTE: start with direct children, recurse up
	// to `depth` levels. The base case sets depth=1; each
	// recursive iteration adds 1 + filters when depth = N.
	//
	// LIMIT clause on the recursive step keeps a chain from
	// runaway-walking if data ever gets corrupted (FK SET
	// NULL + can't-retarget invariants mean cycles are
	// impossible, but defence in depth).
	const sql = `
WITH RECURSIVE chain AS (
  SELECT s.*, 1 AS clone_depth
  FROM scan_schedules s
  WHERE s.source_schedule_id = $1
  UNION ALL
  SELECT s.*, c.clone_depth + 1
  FROM scan_schedules s
  JOIN chain c ON s.source_schedule_id = c.id
  WHERE c.clone_depth < $2
)
SELECT ` + scheduleColumns + `, clone_depth
FROM chain
ORDER BY clone_depth ASC, name ASC`
	rows, err := s.q.Query(ctx, sql, sourceID, depth)
	if err != nil {
		return nil, fmt.Errorf("scanorch: list clones deep: %w", err)
	}
	defer rows.Close()
	out := make([]ScanSchedule, 0)
	for rows.Next() {
		sched, depthVal, scanErr := scanScheduleWithDepth(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		sched.CloneDepth = depthVal
		out = append(out, sched)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanorch: list clones deep (rows): %w", err)
	}
	return out, nil
}

// scanScheduleWithDepth (v2.23+) extends scanSchedule for the
// recursive-CTE projection that includes clone_depth as the
// trailing column.
func scanScheduleWithDepth(rows pgx.Rows) (ScanSchedule, int, error) {
	var (
		s                  ScanSchedule
		templateInput      string
		templatePlugins    []string
		templateDefaultPt  int
		lastFiredAt        *time.Time
		auditRetentionDays *int32
		tags               []string
		sourceScheduleID   *string
		cloneDepth         int32
	)
	if err := rows.Scan(
		&s.ID, &s.Name,
		&templateInput, &templatePlugins, &templateDefaultPt,
		&s.IntervalSeconds, &s.CronExpr, &s.Timezone, &s.Enabled, &s.Operator,
		&s.CreatedAt, &s.UpdatedAt, &lastFiredAt,
		&auditRetentionDays, &tags, &sourceScheduleID,
		&cloneDepth,
	); err != nil {
		return ScanSchedule{}, 0, fmt.Errorf("scanorch: scan schedule (with depth): %w", err)
	}
	s.Template = SubmitRequest{
		Input:       templateInput,
		Plugins:     templatePlugins,
		DefaultPort: templateDefaultPt,
	}
	if lastFiredAt != nil {
		s.LastFiredAt = *lastFiredAt
	}
	if auditRetentionDays != nil {
		s.AuditRetentionDays = int(*auditRetentionDays)
	}
	if len(tags) > 0 {
		s.Tags = tags
	}
	if sourceScheduleID != nil {
		s.SourceScheduleID = *sourceScheduleID
	}
	return s, int(cloneDepth), nil
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
	if err := validateAuditRetention(req.AuditRetentionDays); err != nil {
		return ScanSchedule{}, err
	}
	rows, err := s.updateExec(ctx, id, req)
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

// updateExec dispatches the IfMatch vs. no-precondition SQL
// paths. Returns the pgx.Rows from the RETURNING clause so the
// caller can scan the updated row.
func (s *DBScheduleStore) updateExec(ctx context.Context, id string, req UpdateScheduleRequest) (pgx.Rows, error) {
	plugins := req.Template.Plugins
	if plugins == nil {
		plugins = []string{}
	}
	// Stage the cadence on a temporary ScanSchedule so we
	// reuse applyCadence's "reset both, set one" logic.
	var staged ScanSchedule
	applyCadence(&staged, req.IntervalSeconds, req.CronExpr)
	now := time.Now().UTC().Truncate(time.Microsecond)
	auditDays := auditRetentionDaysToDB(clampAuditRetention(req.AuditRetentionDays))
	tags, _ := canonicaliseTags(req.Tags)
	if tags == nil {
		tags = []string{}
	}
	if req.IfMatch != nil {
		const sqlIfMatch = `
UPDATE scan_schedules
SET name = $2, template_input = $3, template_plugins = $4,
    template_default_port = $5, interval_seconds = $6, cron_expr = $7,
    timezone = $8, updated_at = $10, audit_retention_days = $11, tags = $12
WHERE id = $1 AND updated_at = $9
RETURNING ` + scheduleColumns
		return s.q.Query(ctx, sqlIfMatch,
			id, req.Name, req.Template.Input, plugins, req.Template.DefaultPort,
			staged.IntervalSeconds, staged.CronExpr, req.Timezone, *req.IfMatch, now,
			auditDays, tags,
		)
	}
	const sqlNoMatch = `
UPDATE scan_schedules
SET name = $2, template_input = $3, template_plugins = $4,
    template_default_port = $5, interval_seconds = $6, cron_expr = $7,
    timezone = $8, updated_at = $9, audit_retention_days = $10, tags = $11
WHERE id = $1
RETURNING ` + scheduleColumns
	return s.q.Query(ctx, sqlNoMatch,
		id, req.Name, req.Template.Input, plugins, req.Template.DefaultPort,
		staged.IntervalSeconds, staged.CronExpr, req.Timezone, now,
		auditDays, tags,
	)
}

// TagCounts (v2.5+) aggregates tag occurrences across the
// table via UNNEST + GROUP BY. Sort by count DESC, tag ASC
// for stable dashboard rendering.
func (s *DBScheduleStore) TagCounts(ctx context.Context) ([]TagCount, error) {
	const sql = `
SELECT tag, COUNT(*)::int8 AS n
FROM (SELECT UNNEST(tags) AS tag FROM scan_schedules) t
GROUP BY tag
ORDER BY n DESC, tag ASC`
	rows, err := s.q.Query(ctx, sql)
	if err != nil {
		return nil, fmt.Errorf("scanorch: tag counts: %w", err)
	}
	defer rows.Close()
	var out []TagCount
	for rows.Next() {
		var tc TagCount
		var n int64
		if err := rows.Scan(&tc.Tag, &n); err != nil {
			return nil, fmt.Errorf("scanorch: scan tag count: %w", err)
		}
		tc.Count = int(n)
		out = append(out, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("scanorch: tag counts (rows): %w", err)
	}
	return out, nil
}

// ListByTag (v2.4+) uses the GIN index from migration 00016
// for fast `tags && ARRAY[$1]` overlap filters.
//
// v2.9+: thin wrapper over ListByTags with a single tag.
func (s *DBScheduleStore) ListByTag(ctx context.Context, tag string) ([]ScanSchedule, error) {
	if tag == "" {
		return s.List(ctx)
	}
	return s.ListByTags(ctx, []string{tag}, TagOpAnd)
}

// ListByTags (v2.9+) uses array operators on the v2.4 GIN
// index:
//   - AND     → `tags @> $1::text[]` (contains all).
//   - OR      → `tags && $1::text[]` (overlaps).
//   - not_in  → `NOT (tags && $1::text[])` (no overlap;
//     v2.17+).
//
// AND + OR are GIN-friendly. NOT can't use the GIN index
// directly; the planner falls back to seq scan + filter —
// acceptable for typical fleets (<10k schedules).
func (s *DBScheduleStore) ListByTags(ctx context.Context, tags []string, op string) ([]ScanSchedule, error) {
	if len(tags) == 0 {
		return s.List(ctx)
	}
	var predicate string
	switch op {
	case TagOpOr:
		predicate = "tags && $1::text[]"
	case TagOpNotIn:
		predicate = "NOT (tags && $1::text[])"
	default: // AND
		predicate = "tags @> $1::text[]"
	}
	rows, err := s.q.Query(ctx,
		"SELECT "+scheduleColumns+
			" FROM scan_schedules WHERE "+predicate+
			" ORDER BY name ASC",
		tags)
	if err != nil {
		return nil, fmt.Errorf("scanorch: list schedules by tags: %w", err)
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
		return nil, fmt.Errorf("scanorch: list schedules by tags (rows): %w", err)
	}
	return out, nil
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
		s                  ScanSchedule
		templateInput      string
		templatePlugins    []string
		templateDefaultPt  int
		lastFiredAt        *time.Time
		auditRetentionDays *int32
		tags               []string
		sourceScheduleID   *string
	)
	if err := rows.Scan(
		&s.ID, &s.Name,
		&templateInput, &templatePlugins, &templateDefaultPt,
		&s.IntervalSeconds, &s.CronExpr, &s.Timezone, &s.Enabled, &s.Operator,
		&s.CreatedAt, &s.UpdatedAt, &lastFiredAt,
		&auditRetentionDays, &tags, &sourceScheduleID,
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
	if auditRetentionDays != nil {
		s.AuditRetentionDays = int(*auditRetentionDays)
	}
	if len(tags) > 0 {
		s.Tags = tags
	}
	if sourceScheduleID != nil {
		s.SourceScheduleID = *sourceScheduleID
	}
	return s, nil
}

// auditRetentionDaysToDB maps the Go int (0 = inherit/global)
// to a NULL-able SQL value. 0 → nil → NULL in the column;
// >0 → pointer to the int32 value. We use int32 so the
// underlying pgx driver picks the right column type at bind
// time regardless of platform int size.
//
// The int → int32 conversion is bounded by callers — Create
// + Update clamp via clampAuditRetention to <= 365*10 well
// inside int32 range. Defensive cap below catches any future
// callers that bypass clamping.
func auditRetentionDaysToDB(days int) any {
	if days <= 0 {
		return nil
	}
	if days > scheduleMaxAuditRetentionDays {
		days = scheduleMaxAuditRetentionDays
	}
	v := int32(days) // #nosec G115 — clamped above to fit int32.
	return &v
}

// Compile-time guard.
var _ ScheduleStore = (*DBScheduleStore)(nil)

// silence unused-import warning when build tags strip Querier
// usage paths.
var _ = errors.New
