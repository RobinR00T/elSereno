package repo_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/repo"
)

// fakeQuerier is a minimal repo.Querier for unit tests. It
// understands a hand-rolled script of expected queries → fake
// result sets. Keeping it declarative (rather than a SQL parser)
// means each test owns its expectations.
type fakeQuerier struct {
	rows    []map[string]any
	err     error
	qArgs   []any
	qSQLSub []string // substring markers the SQL must contain; empty = no check
}

func (f *fakeQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if f.err != nil {
		return nil, f.err
	}
	for _, sub := range f.qSQLSub {
		if !containsAll(sql, sub) {
			return nil, errUnexpectedSQL(sql, sub)
		}
	}
	f.qArgs = append([]any(nil), args...)
	return &fakeRows{rows: f.rows}, nil
}

func (f *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return &unusedRow{}
}

func (f *fakeQuerier) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func containsAll(s, sub string) bool {
	return len(sub) == 0 || (len(sub) > 0 && (sub == "" || indexOf(s, sub) >= 0))
}

// indexOf is a tiny substring index without pulling `strings`.
func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 {
		return 0
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}

func errUnexpectedSQL(_, _ string) error {
	return errors.New("unexpected SQL (substring mismatch)")
}

// fakeRows implements pgx.Rows over a hand-rolled slice.
type fakeRows struct {
	rows []map[string]any
	i    int
	err  error
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return r.err }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) Next() bool {
	if r.err != nil {
		return false
	}
	r.i++
	return r.i <= len(r.rows)
}

// Scan wires the current row's named values into dst in the
// order the SQL declares columns. For ListFindings:
//
//	id, run_id, target_id, protocol, severity, score, created_at, factors
//
// For ListRuns:
//
//	id, started_at, finished_at, status, operator, findings
func (r *fakeRows) Scan(dst ...any) error {
	row := r.rows[r.i-1]
	// ListFindings has 8 columns, ListRuns has 6, Triage has 2.
	switch len(dst) {
	case 8:
		return scanFinding(row, dst)
	case 6:
		return scanRun(row, dst)
	case 2:
		return scanTriage(row, dst)
	default:
		return errors.New("fakeRows: unexpected scan arity")
	}
}

// scanFinding / scanRun / scanTriage intentionally panic on a
// type mismatch: the fake rows are built by the test itself, so
// an assertion failure is a programming error the caller wants
// surfaced loudly. forcetypeassert is silenced for that reason.
//
//nolint:forcetypeassert
func scanFinding(row map[string]any, dst []any) error {
	*(dst[0].(*string)) = row["id"].(string)
	*(dst[1].(*string)) = row["run_id"].(string)
	*(dst[2].(*string)) = row["target_id"].(string)
	*(dst[3].(*string)) = row["protocol"].(string)
	*(dst[4].(*string)) = row["severity"].(string)
	*(dst[5].(*int)) = row["score"].(int)
	*(dst[6].(*time.Time)) = row["created_at"].(time.Time)
	if b, ok := row["factors"].([]byte); ok {
		*(dst[7].(*[]byte)) = b
	}
	return nil
}

//nolint:forcetypeassert
func scanRun(row map[string]any, dst []any) error {
	*(dst[0].(*string)) = row["id"].(string)
	*(dst[1].(*time.Time)) = row["started_at"].(time.Time)
	if ft, ok := row["finished_at"].(*time.Time); ok {
		*(dst[2].(**time.Time)) = ft
	}
	*(dst[3].(*string)) = row["status"].(string)
	*(dst[4].(*string)) = row["operator"].(string)
	*(dst[5].(*int)) = row["findings"].(int)
	return nil
}

//nolint:forcetypeassert
func scanTriage(row map[string]any, dst []any) error {
	*(dst[0].(*string)) = row["severity"].(string)
	*(dst[1].(*int64)) = row["count"].(int64)
	return nil
}

type unusedRow struct{}

func (unusedRow) Scan(_ ...any) error { return errors.New("QueryRow not used") }

// Tests --------------------------------------------------------

func TestListFindings_AppliesSeverityFilter(t *testing.T) {
	fq := &fakeQuerier{
		rows: []map[string]any{
			{
				"id": "f1", "run_id": "r1", "target_id": "t1", "protocol": "modbus",
				"severity": "high", "score": 77,
				"created_at": time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC),
				"factors":    []byte(`{"exposure":80}`),
			},
		},
	}
	out, err := repo.ListFindings(context.Background(), fq, repo.FindingsQuery{
		Severity: "high",
		Limit:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Protocol != "modbus" || out[0].Factors["exposure"] != 80 {
		t.Fatalf("unexpected findings: %+v", out)
	}
	// severity is $1, limit is $2.
	if len(fq.qArgs) != 2 || fq.qArgs[0] != "high" || fq.qArgs[1] != 10 {
		t.Fatalf("args = %v, want [high 10]", fq.qArgs)
	}
}

func TestListFindings_DefaultLimitAndNoFilters(t *testing.T) {
	fq := &fakeQuerier{rows: nil}
	_, _ = repo.ListFindings(context.Background(), fq, repo.FindingsQuery{})
	if len(fq.qArgs) != 1 || fq.qArgs[0] != 50 {
		t.Fatalf("default limit: args = %v, want [50]", fq.qArgs)
	}
}

func TestListFindings_ClampsHugeLimit(t *testing.T) {
	fq := &fakeQuerier{rows: nil}
	_, _ = repo.ListFindings(context.Background(), fq, repo.FindingsQuery{Limit: 10_000})
	if fq.qArgs[len(fq.qArgs)-1] != 500 {
		t.Fatalf("max limit: args = %v, want trailing 500", fq.qArgs)
	}
}

func TestListFindings_FactorsCorruptReturnsError(t *testing.T) {
	fq := &fakeQuerier{
		rows: []map[string]any{
			{
				"id": "f1", "run_id": "r1", "target_id": "t1", "protocol": "modbus",
				"severity": "high", "score": 77,
				"created_at": time.Now(),
				"factors":    []byte("{not valid json"),
			},
		},
	}
	_, err := repo.ListFindings(context.Background(), fq, repo.FindingsQuery{})
	if err == nil {
		t.Fatal("expected corrupt-JSON error")
	}
}

func TestListRuns_CorrelatedFindingsCount(t *testing.T) {
	fq := &fakeQuerier{
		rows: []map[string]any{
			{
				"id":          "r1",
				"started_at":  time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC),
				"finished_at": (*time.Time)(nil),
				"status":      "running",
				"operator":    "ci",
				"findings":    12,
			},
			{
				"id":          "r0",
				"started_at":  time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC),
				"finished_at": ptr(time.Date(2026, 4, 20, 1, 0, 0, 0, time.UTC)),
				"status":      "completed",
				"operator":    "ci",
				"findings":    7,
			},
		},
	}
	out, err := repo.ListRuns(context.Background(), fq, repo.RunsQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("runs = %d, want 2", len(out))
	}
	if out[0].Findings != 12 || out[1].Findings != 7 {
		t.Fatalf("findings counts = %d/%d", out[0].Findings, out[1].Findings)
	}
	if out[0].FinishedAt != nil {
		t.Fatalf("run[0] should still be in flight")
	}
	if out[1].FinishedAt == nil {
		t.Fatalf("run[1] must have FinishedAt")
	}
}

func TestTriage_OmitsEmptyBuckets(t *testing.T) {
	fq := &fakeQuerier{
		rows: []map[string]any{
			{"severity": "critical", "count": int64(3)},
			{"severity": "high", "count": int64(7)},
		},
	}
	out, err := repo.Triage(context.Background(), fq)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("triage rows = %d, want 2", len(out))
	}
	if out[0].Severity != "critical" || out[0].Count != 3 {
		t.Fatalf("first bucket = %+v", out[0])
	}
}

// Silence the unused-json-import warning on platforms where the
// test runner skips some cases above.
var _ = json.Marshal

func ptr(t time.Time) *time.Time { return &t }
