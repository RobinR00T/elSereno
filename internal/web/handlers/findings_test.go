package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
