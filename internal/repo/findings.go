package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Querier is the narrow pgx surface the repo package needs. Both
// *pgxpool.Pool and *pgx.Conn satisfy it; tests use an in-memory
// fake.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Finding mirrors the dashboard-facing projection of the
// findings table — the wire shape the `/api/v1/findings`
// handler emits. We deliberately flatten the JSONB `factors`
// column into a `map[string]int` so the JSON envelope matches
// the SSE `finding` event payload byte-for-byte.
type Finding struct {
	ID        string         `json:"id"`
	RunID     string         `json:"run_id"`
	TargetID  string         `json:"target_id"`
	Protocol  string         `json:"protocol"`
	Severity  string         `json:"severity"`
	Score     int            `json:"score"`
	CreatedAt time.Time      `json:"created_at"`
	Factors   map[string]int `json:"factors,omitempty"`
}

// FindingsQuery is the caller-supplied filter for ListFindings.
// Zero values are ignored: an empty Query returns the newest
// page with the default 50-row limit.
type FindingsQuery struct {
	// Severity, if non-empty, restricts the result to this
	// severity (critical/high/medium/low/info).
	Severity string
	// Protocol, if non-empty, restricts to one protocol.
	Protocol string
	// RunID, if non-empty, restricts to findings from a single
	// run (v1.18 chunk 2 — used by the diff endpoint).
	RunID string
	// MinScore filters score ≥ N.
	MinScore int
	// CreatedAfter filters created_at > T. Pair with a cursor
	// from the previous page's last CreatedAt to paginate.
	CreatedAfter time.Time
	// Limit caps the row count. Clamped to [1, 500]; default 50.
	Limit int
}

const (
	findingsDefaultLimit = 50
	findingsMaxLimit     = 500
)

// ListFindings returns the most-recent findings matching q, in
// descending created_at order. Pagination is cursor-based: the
// caller pages forward by passing the oldest returned
// CreatedAt back as CreatedAfter-1µs (so the same row never
// repeats).
func ListFindings(ctx context.Context, q Querier, fq FindingsQuery) ([]Finding, error) {
	limit := clampFindingsLimit(fq.Limit)
	sql, args := buildFindingsQuery(fq, limit)

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("repo: list findings: %w", err)
	}
	defer rows.Close()

	out := make([]Finding, 0, limit)
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repo: findings rows: %w", err)
	}
	return out, nil
}

// clampFindingsLimit normalises the operator-supplied limit to
// [1, findingsMaxLimit], defaulting to findingsDefaultLimit when
// the caller passes 0.
func clampFindingsLimit(n int) int {
	if n <= 0 {
		return findingsDefaultLimit
	}
	if n > findingsMaxLimit {
		return findingsMaxLimit
	}
	return n
}

// buildFindingsQuery renders the parameterised SQL + args slice
// from a FindingsQuery. Split out of ListFindings so the call
// site stays under the funlen threshold and the SQL logic is
// testable in isolation once we ship DB-integration tests.
func buildFindingsQuery(fq FindingsQuery, limit int) (string, []any) {
	var (
		filters []string
		args    []any
	)
	if fq.Severity != "" {
		args = append(args, fq.Severity)
		filters = append(filters, fmt.Sprintf("severity = $%d", len(args)))
	}
	if fq.Protocol != "" {
		args = append(args, fq.Protocol)
		filters = append(filters, fmt.Sprintf("protocol = $%d", len(args)))
	}
	if fq.RunID != "" {
		args = append(args, fq.RunID)
		filters = append(filters, fmt.Sprintf("run_id = $%d", len(args)))
	}
	if fq.MinScore > 0 {
		args = append(args, fq.MinScore)
		filters = append(filters, fmt.Sprintf("score >= $%d", len(args)))
	}
	if !fq.CreatedAfter.IsZero() {
		args = append(args, fq.CreatedAfter)
		filters = append(filters, fmt.Sprintf("created_at > $%d", len(args)))
	}
	where := ""
	if len(filters) > 0 {
		where = "WHERE " + strings.Join(filters, " AND ")
	}
	args = append(args, limit)
	return fmt.Sprintf(`
		SELECT id, run_id, target_id, protocol, severity, score, created_at, factors
		FROM findings
		%s
		ORDER BY created_at DESC
		LIMIT $%d`, where, len(args)), args
}

// FindingsDiff is the categorised diff between two runs'
// findings. v1.18 chunk 2: powers `GET /api/v1/findings/diff?
// old=<old_run_id>&new=<new_run_id>` so operators running
// weekly scans can see what changed (new exposures, fixed
// findings, persisting issues) without grepping JSON.
//
// Match key for cross-run identity is (target_id, protocol):
// the same exposure rediscovered on the next scan is
// "persisting" even though its DB row gets a fresh UUID. The
// per-bucket `Finding.RunID` carries the run that produced the
// exact row included.
type FindingsDiff struct {
	// New are findings in the new run that have no
	// (target_id, protocol) match in the old run.
	New []Finding `json:"new"`
	// Resolved are findings from the old run with no match in
	// the new run — the operator's remediation worked.
	Resolved []Finding `json:"resolved"`
	// Persisting are findings present in both runs (matched by
	// target_id + protocol). The Finding included is from the
	// NEW run so the operator sees the freshest score / factors.
	Persisting []Finding `json:"persisting"`
}

// DiffFindings runs two ListFindings queries (one per run id)
// and categorises the union into new / resolved / persisting.
// Both runs are capped at the same row limit to bound the
// in-memory diff (default 500; clamped to [1, 500]).
//
// Returns an error iff either underlying query fails. Empty
// inputs (one or both runs have no findings) produce a valid
// FindingsDiff with the appropriate buckets empty.
func DiffFindings(ctx context.Context, q Querier, oldRunID, newRunID string) (FindingsDiff, error) {
	const cap = findingsMaxLimit
	oldRows, err := ListFindings(ctx, q, FindingsQuery{RunID: oldRunID, Limit: cap})
	if err != nil {
		return FindingsDiff{}, fmt.Errorf("diff: list old run: %w", err)
	}
	newRows, err := ListFindings(ctx, q, FindingsQuery{RunID: newRunID, Limit: cap})
	if err != nil {
		return FindingsDiff{}, fmt.Errorf("diff: list new run: %w", err)
	}
	return diffFindingsByTargetProtocol(oldRows, newRows), nil
}

// diffFindingsByTargetProtocol bucketises old + new finding
// slices into FindingsDiff. Pure (no DB), exported via
// DiffFindings; extracted so unit tests can exercise the
// matching logic without a Querier.
func diffFindingsByTargetProtocol(oldRows, newRows []Finding) FindingsDiff {
	type key struct {
		targetID, protocol string
	}
	oldByKey := make(map[key]Finding, len(oldRows))
	for _, f := range oldRows {
		oldByKey[key{f.TargetID, f.Protocol}] = f
	}
	newByKey := make(map[key]Finding, len(newRows))
	for _, f := range newRows {
		newByKey[key{f.TargetID, f.Protocol}] = f
	}
	var d FindingsDiff
	for k, f := range newByKey {
		if _, found := oldByKey[k]; found {
			d.Persisting = append(d.Persisting, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for k, f := range oldByKey {
		if _, found := newByKey[k]; !found {
			d.Resolved = append(d.Resolved, f)
		}
	}
	return d
}

// scanFinding pulls one row into a Finding, decoding the JSONB
// factors column. Corrupt JSON in the column is surfaced to the
// caller — the dashboard can still render the row minus
// factors, but operators deserve to know.
func scanFinding(rows interface {
	Scan(dst ...any) error
}) (Finding, error) {
	var f Finding
	var factors []byte
	if err := rows.Scan(&f.ID, &f.RunID, &f.TargetID, &f.Protocol,
		&f.Severity, &f.Score, &f.CreatedAt, &factors); err != nil {
		return Finding{}, fmt.Errorf("repo: scan finding: %w", err)
	}
	if len(factors) > 0 {
		if err := json.Unmarshal(factors, &f.Factors); err != nil {
			return Finding{}, fmt.Errorf("repo: decode factors for %s: %w", f.ID, err)
		}
	}
	return f, nil
}
