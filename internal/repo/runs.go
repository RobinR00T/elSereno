package repo

import (
	"context"
	"fmt"
	"time"
)

// Run mirrors the runs-table projection the dashboard shows.
// Null FinishedAt means the run is still in flight.
type Run struct {
	ID         string     `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	Operator   string     `json:"operator"`
	Findings   int        `json:"findings"`
}

const runsDefaultLimit = 20
const runsMaxLimit = 100

// RunsQuery filters ListRuns. Zero values → newest 20 rows.
type RunsQuery struct {
	// Status, if non-empty, restricts to one status.
	Status string
	// StartedAfter filters started_at > T for cursor pagination.
	StartedAfter time.Time
	// Limit clamped to [1, 100]; default 20.
	Limit int
}

// ListRuns returns the newest runs matching q in descending
// started_at order, annotated with a correlated COUNT() of
// findings per run. Fewer rows than `runs` means the pagination
// cursor consumer should keep reading.
func ListRuns(ctx context.Context, q Querier, rq RunsQuery) ([]Run, error) {
	limit := rq.Limit
	if limit <= 0 {
		limit = runsDefaultLimit
	}
	if limit > runsMaxLimit {
		limit = runsMaxLimit
	}
	var (
		filters []string
		args    []any
	)
	if rq.Status != "" {
		args = append(args, rq.Status)
		filters = append(filters, fmt.Sprintf("r.status = $%d", len(args)))
	}
	if !rq.StartedAfter.IsZero() {
		args = append(args, rq.StartedAfter)
		filters = append(filters, fmt.Sprintf("r.started_at > $%d", len(args)))
	}
	where := ""
	if len(filters) > 0 {
		where = "WHERE " + joinAnd(filters)
	}
	args = append(args, limit)
	sql := fmt.Sprintf(`
		SELECT r.id,
		       r.started_at,
		       r.finished_at,
		       r.status,
		       COALESCE(r.operator, '') AS operator,
		       COALESCE((SELECT COUNT(*) FROM findings f WHERE f.run_id = r.id), 0) AS findings
		FROM runs r
		%s
		ORDER BY r.started_at DESC
		LIMIT $%d`, where, len(args))

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: list runs: %w", err)
	}
	defer rows.Close()

	out := make([]Run, 0, limit)
	for rows.Next() {
		var r Run
		var finished *time.Time
		if err := rows.Scan(&r.ID, &r.StartedAt, &finished, &r.Status, &r.Operator, &r.Findings); err != nil {
			return nil, fmt.Errorf("repo: scan run: %w", err)
		}
		r.FinishedAt = finished
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: runs rows: %w", err)
	}
	return out, nil
}

// TriageBucket summarises findings by severity. Returned once
// per severity; the dashboard renders these as chips + counts.
type TriageBucket struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// Triage returns the per-severity count across all findings.
// Severities that have zero findings are OMITTED; the dashboard
// displays only non-zero severities to avoid a row of empty
// chips.
func Triage(ctx context.Context, q Querier) ([]TriageBucket, error) {
	rows, err := q.Query(ctx, `
		SELECT severity, COUNT(*)::bigint
		FROM findings
		GROUP BY severity
		ORDER BY CASE severity
		           WHEN 'critical' THEN 0
		           WHEN 'high'     THEN 1
		           WHEN 'medium'   THEN 2
		           WHEN 'low'      THEN 3
		           WHEN 'info'     THEN 4
		           ELSE 5
		         END`)
	if err != nil {
		return nil, fmt.Errorf("repo: triage: %w", err)
	}
	defer rows.Close()
	// Return an empty slice (not nil) when there are no rows so
	// the JSON serializer renders `[]` rather than `null` — the
	// dashboard JS doesn't have to special-case either value,
	// but a consumer parsing the envelope schema strictly would.
	out := []TriageBucket{}
	for rows.Next() {
		var t TriageBucket
		var n int64
		if err := rows.Scan(&t.Severity, &n); err != nil {
			return nil, fmt.Errorf("repo: scan triage: %w", err)
		}
		t.Count = int(n)
		out = append(out, t)
	}
	return out, rows.Err()
}

// joinAnd is a tiny helper that wraps strings.Join to keep the
// list-findings path (which uses a full import) symmetric with
// list-runs. Duplicated across files to keep each file
// independently readable.
func joinAnd(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += " AND "
		}
		out += v
	}
	return out
}
