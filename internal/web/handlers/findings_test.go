package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/web/handlers"
)

// findingsFake implements repo.Querier enough to drive the
// handlers' happy-path + error-path tests.
type findingsFake struct {
	err  error
	rows []any // arbitrary shape; Rows delegates to scanner closures
}

func (f *findingsFake) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &findingsRows{rows: f.rows}, nil
}

func (f *findingsFake) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return nil
}

func (f *findingsFake) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

type findingsRows struct {
	rows []any
	i    int
}

func (r *findingsRows) Close()                                       {}
func (r *findingsRows) Err() error                                   { return nil }
func (r *findingsRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *findingsRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *findingsRows) Conn() *pgx.Conn                              { return nil }
func (r *findingsRows) RawValues() [][]byte                          { return nil }
func (r *findingsRows) Values() ([]any, error)                       { return nil, nil }
func (r *findingsRows) Next() bool                                   { r.i++; return r.i <= len(r.rows) }

// Scan populates dst from a canned row shape. The test fake
// intentionally panics on a type mismatch — the fake is wired
// by the handler's parameterised SQL, so a wrong dst type means
// the handler changed and the fake needs an update.
//
//nolint:forcetypeassert
func (r *findingsRows) Scan(dst ...any) error {
	switch len(dst) {
	case 8:
		// Findings layout
		*(dst[0].(*string)) = "f1"
		*(dst[1].(*string)) = "r1"
		*(dst[2].(*string)) = "t1"
		*(dst[3].(*string)) = "modbus"
		*(dst[4].(*string)) = "high"
		*(dst[5].(*int)) = 77
		*(dst[6].(*time.Time)) = time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC)
		*(dst[7].(*[]byte)) = []byte(`{"exposure":80}`)
	case 6:
		// Runs layout
		*(dst[0].(*string)) = "r1"
		*(dst[1].(*time.Time)) = time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC)
		*(dst[2].(**time.Time)) = nil
		*(dst[3].(*string)) = "running"
		*(dst[4].(*string)) = "ci"
		*(dst[5].(*int)) = 12
	case 2:
		// Triage layout
		*(dst[0].(*string)) = "high"
		*(dst[1].(*int64)) = 7
	}
	return nil
}

// TestFindings_NilQuerierReturns503 — the dashboard must be
// able to render even when the DB isn't configured; the API
// endpoint signals that with a 503 + a clear body.
func TestFindings_NilQuerierReturns503(t *testing.T) {
	h := handlers.APIV1(handlers.APIV1Deps{})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/findings", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestFindings_HappyPath(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/findings?severity=high", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	body, _ := io.ReadAll(rec.Body)
	var env struct {
		Schema string `json:"schema"`
		Data   []any  `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Schema != "api:v1" {
		t.Fatalf("schema = %q", env.Schema)
	}
	if len(env.Data) != 1 {
		t.Fatalf("rows = %d, want 1", len(env.Data))
	}
}

// TestFindings_CSVFormat — v1.18 chunk 1: the CSV format
// emits text/csv with a download disposition + RFC-4180 body.
func TestFindings_CSVFormat(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/findings?format=csv&severity=high", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv prefix", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, `attachment; filename="findings-`) {
		t.Errorf("Content-Disposition = %q, want attachment with findings- filename", cd)
	}
	body := rec.Body.String()
	// Header row + 1 data row; final empty line is RFC4180.
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("CSV has %d lines, want >= 2 (header + 1 data row): %q", len(lines), body)
	}
	if !strings.HasPrefix(lines[0], "id,run_id,target_id,protocol,severity,score,created_at,factors") {
		t.Errorf("CSV header = %q; want canonical column order", lines[0])
	}
	// Data row contains the canned high-severity finding.
	if !strings.Contains(lines[1], "f1,r1,t1,modbus,high,77,2026-04-21T00:00:00Z") {
		t.Errorf("CSV data row = %q; want canned f1/r1/t1/modbus/high/77/2026-04-21 row", lines[1])
	}
	// Factors are rendered as name=value;... — canned factors
	// has only `exposure=80`.
	if !strings.Contains(lines[1], "exposure=80") {
		t.Errorf("CSV factors column missing exposure=80: %q", lines[1])
	}
}

// TestFindings_CSVCaseInsensitive — `format=CSV` (any case)
// also triggers CSV.
func TestFindings_CSVCaseInsensitive(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/findings?format=CSV", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q for format=CSV; want text/csv (case-insensitive match)", ct)
	}
}

// TestFindings_NoFormatDefaultsToJSON — backwards-compat: no
// format param keeps the v1.2 JSON envelope.
func TestFindings_NoFormatDefaultsToJSON(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/findings", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("default Content-Type = %q, want application/json (backwards-compat)", ct)
	}
}

func TestFindings_QueryErrorReturns500(t *testing.T) {
	fq := &findingsFake{err: errors.New("simulated")}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/findings", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// TestFindingsDiff_NilQuerierReturns503 — same dashboard
// resilience contract as Findings: no DB → 503.
func TestFindingsDiff_NilQuerierReturns503(t *testing.T) {
	h := handlers.APIV1(handlers.APIV1Deps{})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"/api/v1/findings/diff?old=r1&new=r2", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestFindingsDiff_RequiresBothRunIDs — missing old= or new=
// returns 400 with a usage hint.
func TestFindingsDiff_RequiresBothRunIDs(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	for _, qs := range []string{"", "old=r1", "new=r2"} {
		t.Run(qs, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet,
				"/api/v1/findings/diff?"+qs, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d for query %q, want 400", rec.Code, qs)
			}
		})
	}
}

// TestFindingsDiff_RejectsSameRunID — old == new is a usage
// error (the diff would be trivially empty, which is more
// likely an operator typo than intentional).
func TestFindingsDiff_RejectsSameRunID(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"/api/v1/findings/diff?old=r1&new=r1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for old==new, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "distinct run ids") {
		t.Errorf("body = %q; want mention of distinct run ids", rec.Body.String())
	}
}

// TestFindingsDiff_HappyPath — both runs populated, returns
// the categorised envelope.
func TestFindingsDiff_HappyPath(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"/api/v1/findings/diff?old=r1&new=r2", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Schema string `json:"schema"`
		Data   struct {
			New        []any `json:"new"`
			Resolved   []any `json:"resolved"`
			Persisting []any `json:"persisting"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Schema != "api:v1" {
		t.Errorf("schema = %q, want api:v1", env.Schema)
	}
	// The fake returns 1 row per query; both old and new
	// queries share the canned (target_id=t1, protocol=modbus)
	// shape, so both rows fall in the persisting bucket.
	if len(env.Data.Persisting) != 1 {
		t.Errorf("persisting = %d, want 1 (the canned fake makes both runs return the same (target,protocol))", len(env.Data.Persisting))
	}
}

func TestRuns_HappyPath(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/runs", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestTriage_HappyPath(t *testing.T) {
	fq := &findingsFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: fq})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/triage", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
}
