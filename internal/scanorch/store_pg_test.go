package scanorch_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/scanorch"
)

// fakeQuerier is a minimal scanorch.Querier for unit tests. It
// captures the executed SQL + args, returns canned rows, and
// (for transition tests) lets the test inject a "0 rows
// updated" outcome via the upd0 flag.
type fakeQuerier struct {
	mu sync.Mutex

	// queryRows is the slice returned by the next Query call.
	queryRows []map[string]any
	// queryErr is returned by the next Query call.
	queryErr error
	// transitionUpdateRows is the slice returned by Query calls
	// that target the UPDATE ... RETURNING shape. Empty slice
	// → simulates "0 rows updated", which triggers the
	// classifyTransitionMiss follow-up.
	transitionUpdateRows []map[string]any
	// classifyExistsRows is what the follow-up SELECT returns.
	// One row → ErrInvalidTransition; zero rows → ErrJobNotFound.
	classifyExistsRows []map[string]any

	// captured state from the last call
	lastSQL  string
	lastArgs []any

	// queryCallCount counts Query() invocations so transition
	// tests can route the first call to the UPDATE-RETURNING
	// rows and the second to the classify-existence rows.
	queryCallCount int

	// execRowsAffected lets v1.71 schedule tests configure the
	// CommandTag returned by Exec. Defaults to 0; schedule
	// tests bump to 1 to simulate "row found + updated".
	execRowsAffected int
}

func (f *fakeQuerier) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queryCallCount++
	f.lastSQL = sql
	f.lastArgs = append([]any(nil), args...)
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	// Route based on whether this looks like an UPDATE-RETURNING
	// (first call when transitionUpdateRows is set) vs a SELECT.
	if strings.HasPrefix(strings.TrimSpace(sql), "UPDATE") {
		return &fakeRows{rows: f.transitionUpdateRows}, nil
	}
	if f.queryCallCount > 1 && f.classifyExistsRows != nil {
		return &fakeRows{rows: f.classifyExistsRows}, nil
	}
	return &fakeRows{rows: f.queryRows}, nil
}

func (f *fakeQuerier) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return &errRow{}
}

func (f *fakeQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastSQL = sql
	f.lastArgs = append([]any(nil), args...)
	if f.execRowsAffected > 0 {
		// pgconn.CommandTag is constructed from a server-style
		// "TAG N" string. "UPDATE 1" → RowsAffected() == 1.
		return pgconn.NewCommandTag(fmt.Sprintf("UPDATE %d", f.execRowsAffected)), nil
	}
	return pgconn.CommandTag{}, nil
}

type errRow struct{}

func (errRow) Scan(_ ...any) error { return errors.New("QueryRow not used") }

// fakeRows mimics the pgx.Rows surface scanorch needs. The Scan
// implementation hand-decodes the 13-column scan-jobs
// projection.
type fakeRows struct {
	rows []map[string]any
	i    int
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, nil }
func (r *fakeRows) Next() bool {
	r.i++
	return r.i <= len(r.rows)
}

// Scan unpacks the test row map into the requested column
// destinations. Shapes:
//
//   - 16 columns → scan_schedules v2.10+ projection
//     (source_schedule_id appended after tags).
//   - 15 columns → AMBIGUOUS:
//     · scan_jobs v1.92+ (triggered_by_schedule_id).
//     · scan_schedules v2.4-v2.9 (tags but no source).
//     Disambiguated by dst[2] type.
//   - 14 columns → AMBIGUOUS:
//     · scan_jobs pre-v1.92.
//     · scan_schedules v1.89-v2.3.
//     Same dst[2]-type disambiguation.
//   - 13 columns → scan_schedules pre-v1.89.
//   - 1 column → existence-check projection.
//
//nolint:forcetypeassert // test fixture; assertion failure is a programming error
func (r *fakeRows) Scan(dst ...any) error {
	row := r.rows[r.i-1]
	switch len(dst) {
	case 16:
		// v2.10 scan_schedules projection only.
		return scanFakeSchedule(dst, row)
	case 15:
		if _, isString := dst[2].(*string); isString {
			return scanFakeSchedule(dst, row)
		}
		return scanFakeJob(dst, row)
	case 14:
		if _, isString := dst[2].(*string); isString {
			return scanFakeSchedule(dst, row)
		}
		return scanFakeJob(dst, row)
	case 13:
		return scanFakeSchedule(dst, row)
	case 1:
		// Existence-check uses `SELECT 1`. We only ever Next()
		// against this — the caller doesn't Scan(1). Implement
		// for completeness so a future test can.
		if v, ok := dst[0].(*int); ok {
			*v = 1
		}
		return nil
	default:
		return fmt.Errorf("fakeRows: scanorch test expected 16, 15, 14, 13, or 1 columns, got %d", len(dst))
	}
}

//nolint:forcetypeassert // test fixture
func scanFakeJob(dst []any, row map[string]any) error {
	*(dst[0].(*string)) = row["id"].(string)
	*(dst[1].(*string)) = row["state"].(string)
	*(dst[2].(*time.Time)) = row["created_at"].(time.Time)
	if v, ok := row["started_at"].(*time.Time); ok {
		*(dst[3].(**time.Time)) = v
	}
	if v, ok := row["finished_at"].(*time.Time); ok {
		*(dst[4].(**time.Time)) = v
	}
	*(dst[5].(*string)) = row["input"].(string)
	if v, ok := row["plugins"].([]string); ok {
		*(dst[6].(*[]string)) = v
	}
	*(dst[7].(*int)) = row["default_port"].(int)
	*(dst[8].(*int64)) = row["targets_seen"].(int64)
	*(dst[9].(*int64)) = row["targets_scanned"].(int64)
	*(dst[10].(*int64)) = row["findings_count"].(int64)
	*(dst[11].(*string)) = row["error_msg"].(string)
	*(dst[12].(*string)) = row["operator"].(string)
	if v, ok := row["findings_by_plugin"].([]byte); ok {
		*(dst[13].(*[]byte)) = v
	}
	// v1.92: triggered_by_schedule_id NULL-able column. Only
	// present in the 15-column projection; legacy 14-col tests
	// don't pass this dst slot.
	if len(dst) >= 15 {
		if v, ok := row["triggered_by_schedule_id"].(*string); ok {
			*(dst[14].(**string)) = v
		}
	}
	return nil
}

//nolint:forcetypeassert // test fixture
func scanFakeSchedule(dst []any, row map[string]any) error {
	*(dst[0].(*string)) = row["id"].(string)
	*(dst[1].(*string)) = row["name"].(string)
	*(dst[2].(*string)) = row["template_input"].(string)
	if v, ok := row["template_plugins"].([]string); ok {
		*(dst[3].(*[]string)) = v
	}
	*(dst[4].(*int)) = row["template_default_port"].(int)
	*(dst[5].(*int)) = row["interval_seconds"].(int)
	*(dst[6].(*string)) = row["cron_expr"].(string)
	*(dst[7].(*string)) = row["timezone"].(string)
	*(dst[8].(*bool)) = row["enabled"].(bool)
	*(dst[9].(*string)) = row["operator"].(string)
	*(dst[10].(*time.Time)) = row["created_at"].(time.Time)
	*(dst[11].(*time.Time)) = row["updated_at"].(time.Time)
	if v, ok := row["last_fired_at"].(*time.Time); ok {
		*(dst[12].(**time.Time)) = v
	}
	// v1.89: audit_retention_days NULL-able column appended
	// at the tail. Only present in the 14-column projection;
	// the legacy 13-column tests don't pass this dst slot.
	if len(dst) >= 14 {
		if v, ok := row["audit_retention_days"].(*int32); ok {
			*(dst[13].(**int32)) = v
		}
	}
	// v2.4: tags column TEXT[]. Only in 15-column projection
	// (and onwards).
	if len(dst) >= 15 {
		if v, ok := row["tags"].([]string); ok {
			*(dst[14].(*[]string)) = v
		}
	}
	// v2.10: source_schedule_id NULL-able TEXT. Only in
	// 16-column projection.
	if len(dst) >= 16 {
		if v, ok := row["source_schedule_id"].(*string); ok {
			*(dst[15].(**string)) = v
		}
	}
	return nil
}

// makeRow returns a baseline scan_jobs row with the given
// state. Tests override individual columns as needed.
func makeRow(id, state string) map[string]any {
	return map[string]any{
		"id":                       id,
		"state":                    state,
		"created_at":               time.Now().UTC(),
		"input":                    "stdin",
		"plugins":                  []string{},
		"default_port":             int(0),
		"targets_seen":             int64(0),
		"targets_scanned":          int64(0),
		"findings_count":           int64(0),
		"error_msg":                "",
		"operator":                 "alice",
		"findings_by_plugin":       []byte(`{}`),
		"triggered_by_schedule_id": (*string)(nil),
	}
}

// TestDBStore_Submit_Happy: INSERT round-trip.
func TestDBStore_Submit_Happy(t *testing.T) {
	q := &fakeQuerier{}
	store := scanorch.NewDBStore(q)
	job, err := store.Submit(context.Background(),
		scanorch.SubmitRequest{Input: "list:t.txt", Plugins: []string{"modbus"}, DefaultPort: 502},
		"alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.State != scanorch.StateQueued {
		t.Errorf("State = %q", job.State)
	}
	if job.Operator != "alice" {
		t.Errorf("Operator = %q", job.Operator)
	}
	if !strings.Contains(q.lastSQL, "INSERT INTO scan_jobs") {
		t.Errorf("expected INSERT, got: %s", q.lastSQL)
	}
}

// TestDBStore_Submit_InputRequired short-circuits before the
// SQL is built.
func TestDBStore_Submit_InputRequired(t *testing.T) {
	q := &fakeQuerier{}
	store := scanorch.NewDBStore(q)
	_, err := store.Submit(context.Background(), scanorch.SubmitRequest{}, "alice")
	if !errors.Is(err, scanorch.ErrInputRequired) {
		t.Errorf("err = %v, want ErrInputRequired", err)
	}
}

// TestDBStore_Get_Happy returns a job from one row.
func TestDBStore_Get_Happy(t *testing.T) {
	q := &fakeQuerier{queryRows: []map[string]any{makeRow("abc123", "queued")}}
	store := scanorch.NewDBStore(q)
	job, err := store.Get(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.ID != "abc123" {
		t.Errorf("ID = %q", job.ID)
	}
	if job.State != scanorch.StateQueued {
		t.Errorf("State = %q", job.State)
	}
}

// TestDBStore_Get_NotFound returns the sentinel.
func TestDBStore_Get_NotFound(t *testing.T) {
	q := &fakeQuerier{queryRows: nil}
	store := scanorch.NewDBStore(q)
	_, err := store.Get(context.Background(), "missing")
	if !errors.Is(err, scanorch.ErrJobNotFound) {
		t.Errorf("err = %v, want ErrJobNotFound", err)
	}
}

// TestDBStore_List returns multiple rows + clamps the limit.
func TestDBStore_List(t *testing.T) {
	q := &fakeQuerier{queryRows: []map[string]any{
		makeRow("a", "completed"),
		makeRow("b", "queued"),
	}}
	store := scanorch.NewDBStore(q)
	jobs, err := store.List(context.Background(), 5)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(jobs) != 2 {
		t.Errorf("len(jobs) = %d, want 2", len(jobs))
	}
	if !strings.Contains(q.lastSQL, "ORDER BY created_at DESC") {
		t.Errorf("expected ORDER BY clause: %s", q.lastSQL)
	}
}

// TestDBStore_List_LimitClamp passes 0 → defaults to 20.
func TestDBStore_List_LimitClamp(t *testing.T) {
	q := &fakeQuerier{queryRows: nil}
	store := scanorch.NewDBStore(q)
	_, err := store.List(context.Background(), 0)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// limit arg should be 20
	if len(q.lastArgs) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(q.lastArgs))
	}
	if got, ok := q.lastArgs[0].(int); !ok || got != 20 {
		t.Errorf("limit arg = %v, want 20", q.lastArgs[0])
	}
}

// TestDBStore_Transition_Happy: queued → running succeeds.
func TestDBStore_Transition_Happy(t *testing.T) {
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{makeRow("abc", "running")}}
	store := scanorch.NewDBStore(q)
	job, err := store.Transition(context.Background(), "abc", scanorch.StateRunning, scanorch.TransitionFields{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.State != scanorch.StateRunning {
		t.Errorf("State = %q", job.State)
	}
	if !strings.Contains(q.lastSQL, "UPDATE scan_jobs") {
		t.Errorf("expected UPDATE, got: %s", q.lastSQL)
	}
}

// TestDBStore_Transition_InvalidEdge: 0-rows update + the
// classifying SELECT returns the row → ErrInvalidTransition.
func TestDBStore_Transition_InvalidEdge(t *testing.T) {
	q := &fakeQuerier{
		transitionUpdateRows: nil, // 0 rows updated
		classifyExistsRows:   []map[string]any{makeRow("abc", "completed")},
	}
	store := scanorch.NewDBStore(q)
	_, err := store.Transition(context.Background(), "abc", scanorch.StateRunning, scanorch.TransitionFields{})
	if !errors.Is(err, scanorch.ErrInvalidTransition) {
		t.Errorf("err = %v, want ErrInvalidTransition", err)
	}
}

// TestDBStore_Transition_NotFound: 0-rows update + the
// classifying SELECT returns 0 rows → ErrJobNotFound.
func TestDBStore_Transition_NotFound(t *testing.T) {
	q := &fakeQuerier{
		transitionUpdateRows: nil,
		classifyExistsRows:   nil,
	}
	store := scanorch.NewDBStore(q)
	_, err := store.Transition(context.Background(), "missing", scanorch.StateRunning, scanorch.TransitionFields{})
	if !errors.Is(err, scanorch.ErrJobNotFound) {
		t.Errorf("err = %v, want ErrJobNotFound", err)
	}
}

// TestDBStore_Transition_RunningToCompleted carries Stats.
func TestDBStore_Transition_RunningToCompleted(t *testing.T) {
	row := makeRow("abc", "completed")
	row["targets_seen"] = int64(100)
	row["findings_count"] = int64(5)
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{row}}
	store := scanorch.NewDBStore(q)
	stats := scanorch.Stats{TargetsSeen: 100, TargetsScanned: 100, FindingsCount: 5}
	job, err := store.Transition(context.Background(), "abc", scanorch.StateCompleted, scanorch.TransitionFields{Stats: &stats})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.Stats.TargetsSeen != 100 {
		t.Errorf("Stats.TargetsSeen = %d", job.Stats.TargetsSeen)
	}
	// Verify the UPDATE clause carried the stats columns.
	if !strings.Contains(q.lastSQL, "targets_seen") || !strings.Contains(q.lastSQL, "findings_count") {
		t.Errorf("expected stats columns in SQL: %s", q.lastSQL)
	}
}

// TestDBStore_Transition_RunningToFailed carries error_msg.
func TestDBStore_Transition_RunningToFailed(t *testing.T) {
	row := makeRow("abc", "failed")
	row["error_msg"] = "boom"
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{row}}
	store := scanorch.NewDBStore(q)
	job, err := store.Transition(context.Background(), "abc", scanorch.StateFailed, scanorch.TransitionFields{Error: "boom"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.Error != "boom" {
		t.Errorf("Error = %q", job.Error)
	}
}

// TestDBStore_Transition_QueuedToCancelled is allowed.
func TestDBStore_Transition_QueuedToCancelled(t *testing.T) {
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{makeRow("abc", "cancelled")}}
	store := scanorch.NewDBStore(q)
	job, err := store.Transition(context.Background(), "abc", scanorch.StateCancelled, scanorch.TransitionFields{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.State != scanorch.StateCancelled {
		t.Errorf("State = %q", job.State)
	}
}

// TestDBStore_Transition_UnknownTo refuses transitions to
// states that have no valid from-states (e.g., back to
// queued).
func TestDBStore_Transition_UnknownTo(t *testing.T) {
	q := &fakeQuerier{}
	store := scanorch.NewDBStore(q)
	_, err := store.Transition(context.Background(), "abc", scanorch.StateQueued, scanorch.TransitionFields{})
	if !errors.Is(err, scanorch.ErrInvalidTransition) {
		t.Errorf("err = %v, want ErrInvalidTransition", err)
	}
}

// TestDBStore_SatisfiesStoreInterface: compile-time check that
// DBStore is a Store. Already enforced by the package guard,
// but a runtime assertion gives a clearer test failure if the
// guard is removed.
func TestDBStore_SatisfiesStoreInterface(_ *testing.T) {
	var _ scanorch.Store = scanorch.NewDBStore(&fakeQuerier{})
}

// TestDBStore_Transition_PersistsFindingsByPlugin: a completed
// transition with FindingsByPlugin in TransitionFields must
// land in the SQL UPDATE clause, and the returned Job must
// reflect the round-trip.
func TestDBStore_Transition_PersistsFindingsByPlugin(t *testing.T) {
	row := makeRow("abc", "completed")
	row["findings_by_plugin"] = []byte(`{"modbus":3,"s7":2}`)
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{row}}
	store := scanorch.NewDBStore(q)
	stats := scanorch.Stats{TargetsSeen: 100, TargetsScanned: 100, FindingsCount: 5}
	job, err := store.Transition(context.Background(), "abc", scanorch.StateCompleted, scanorch.TransitionFields{
		Stats:            &stats,
		FindingsByPlugin: map[string]int{"modbus": 3, "s7": 2},
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.FindingsByPlugin == nil {
		t.Fatal("FindingsByPlugin should be populated")
	}
	if job.FindingsByPlugin["modbus"] != 3 || job.FindingsByPlugin["s7"] != 2 {
		t.Errorf("FindingsByPlugin = %+v", job.FindingsByPlugin)
	}
	// The SQL must have included the new column.
	if !strings.Contains(q.lastSQL, "findings_by_plugin") {
		t.Errorf("expected findings_by_plugin in SQL: %s", q.lastSQL)
	}
}

// TestDBStore_Transition_NilFindingsByPluginYieldsEmptyJSON:
// a nil/empty map encodes to {} so the column never holds NULL.
func TestDBStore_Transition_NilFindingsByPluginYieldsEmptyJSON(t *testing.T) {
	row := makeRow("abc", "completed")
	q := &fakeQuerier{transitionUpdateRows: []map[string]any{row}}
	store := scanorch.NewDBStore(q)
	stats := scanorch.Stats{}
	if _, err := store.Transition(context.Background(), "abc", scanorch.StateCompleted, scanorch.TransitionFields{
		Stats: &stats,
	}); err != nil {
		t.Fatalf("err = %v", err)
	}
	// The bound arg for findings_by_plugin should be []byte("{}").
	// It's the last arg in the slice (after now, seen, scanned,
	// findings, error).
	if len(q.lastArgs) < 1 {
		t.Fatal("no args captured")
	}
	last := q.lastArgs[len(q.lastArgs)-1]
	bs, ok := last.([]byte)
	if !ok {
		t.Fatalf("last arg = %T, want []byte", last)
	}
	if string(bs) != "{}" {
		t.Errorf("last arg = %q, want '{}'", bs)
	}
}

// TestDBStore_Get_DecodesFindingsByPlugin pins the JSON ->
// map round trip on the SELECT path.
func TestDBStore_Get_DecodesFindingsByPlugin(t *testing.T) {
	row := makeRow("abc", "completed")
	row["findings_by_plugin"] = []byte(`{"banner":1,"modbus":4}`)
	q := &fakeQuerier{queryRows: []map[string]any{row}}
	store := scanorch.NewDBStore(q)
	job, err := store.Get(context.Background(), "abc")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.FindingsByPlugin["banner"] != 1 || job.FindingsByPlugin["modbus"] != 4 {
		t.Errorf("FindingsByPlugin = %+v", job.FindingsByPlugin)
	}
}

// TestDBStore_Get_EmptyJSONBYieldsNilMap: the column default
// '{}' decodes to a nil map (omitempty in JSON output).
func TestDBStore_Get_EmptyJSONBYieldsNilMap(t *testing.T) {
	row := makeRow("abc", "queued")
	row["findings_by_plugin"] = []byte(`{}`)
	q := &fakeQuerier{queryRows: []map[string]any{row}}
	store := scanorch.NewDBStore(q)
	job, err := store.Get(context.Background(), "abc")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.FindingsByPlugin != nil {
		t.Errorf("FindingsByPlugin = %+v, want nil for empty JSONB", job.FindingsByPlugin)
	}
}
