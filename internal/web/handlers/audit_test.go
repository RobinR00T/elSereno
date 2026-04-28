package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/web/handlers"
)

// auditFake implements repo.Querier for the audit handler
// tests. Distinct from findingsFake so the canned scan layout
// doesn't conflict.
type auditFake struct {
	rows []any
}

func (f *auditFake) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return &auditRows{rows: f.rows}, nil
}
func (f *auditFake) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return nil
}
func (f *auditFake) Exec(_ context.Context, _ string, _ ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

type auditRows struct {
	rows []any
	i    int
}

func (r *auditRows) Close()                                       {}
func (r *auditRows) Err() error                                   { return nil }
func (r *auditRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *auditRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *auditRows) Conn() *pgx.Conn                              { return nil }
func (r *auditRows) RawValues() [][]byte                          { return nil }
func (r *auditRows) Values() ([]any, error)                       { return nil, nil }
func (r *auditRows) Next() bool                                   { r.i++; return r.i <= len(r.rows) }

// Scan dispatches by argument count: 6 = ListAuditLog (id /
// occurred_at / actor / event_type / payload / tombstoned), 3
// = ListAuditCadence (day / event_type / count). Mirrors the
// findingsFake pattern.
//
//nolint:forcetypeassert
func (r *auditRows) Scan(dst ...any) error {
	switch len(dst) {
	case 6:
		*(dst[0].(*int64)) = 42
		*(dst[1].(*time.Time)) = time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
		*(dst[2].(*string)) = "operator"
		*(dst[3].(*string)) = "proxy_allowlist_reload"
		*(dst[4].(*[]byte)) = []byte(`{"status":"ok","plugin":"sip"}`)
		*(dst[5].(*bool)) = false
	case 3:
		*(dst[0].(*time.Time)) = time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC)
		*(dst[1].(*string)) = "proxy_allowlist_reload"
		*(dst[2].(*int64)) = 5
	}
	return nil
}

// TestAudit_NilQuerierReturns503 — dashboard renders without
// DB; API endpoint signals 503.
func TestAudit_NilQuerierReturns503(t *testing.T) {
	h := handlers.APIV1(handlers.APIV1Deps{})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/audit", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestAudit_HappyPath — single canned row returns through the
// JSON envelope; payload renders as JSON object (not bytes).
func TestAudit_HappyPath(t *testing.T) {
	q := &auditFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: q})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"/api/v1/audit?event_type=proxy_allowlist_reload&limit=10", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var env struct {
		Schema string `json:"schema"`
		Data   []struct {
			ID         int64           `json:"id"`
			Actor      string          `json:"actor"`
			EventType  string          `json:"event_type"`
			Payload    json.RawMessage `json:"payload"`
			Tombstoned bool            `json:"tombstoned"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v\nbody=%s", err, rec.Body.String())
	}
	if env.Schema != "api:v1" {
		t.Errorf("schema = %q, want api:v1", env.Schema)
	}
	if len(env.Data) != 1 {
		t.Fatalf("rows = %d, want 1", len(env.Data))
	}
	r := env.Data[0]
	if r.ID != 42 || r.Actor != "operator" || r.EventType != "proxy_allowlist_reload" {
		t.Errorf("row = %+v; want canned (42, operator, proxy_allowlist_reload)", r)
	}
	// Normalise whitespace before comparing — writeJSON may
	// emit indented JSON depending on the dashboard's pretty-
	// print toggle.
	if !strings.Contains(strings.ReplaceAll(string(r.Payload), " ", ""), `"plugin":"sip"`) {
		t.Errorf("payload = %s; want contain plugin:sip", string(r.Payload))
	}
}

// TestAudit_FilterIgnoresInvalidLimit — non-int `limit=` falls
// back to the default rather than 400'ing.
func TestAudit_FilterIgnoresInvalidLimit(t *testing.T) {
	q := &auditFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: q})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"/api/v1/audit?limit=not-a-number", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (invalid int should silently default)", rec.Code)
	}
}

// TestAuditCadence_NilQuerierReturns503.
func TestAuditCadence_NilQuerierReturns503(t *testing.T) {
	h := handlers.APIV1(handlers.APIV1Deps{})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/audit/cadence", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestAuditCadence_HappyPath — defaults to 7 days; canned 1
// row returns through the envelope.
func TestAuditCadence_HappyPath(t *testing.T) {
	q := &auditFake{rows: []any{1}}
	h := handlers.APIV1(handlers.APIV1Deps{Querier: q})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet,
		"/api/v1/audit/cadence?event_type=proxy_allowlist_reload&days=7", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var env struct {
		Data []struct {
			Day       time.Time `json:"day"`
			EventType string    `json:"event_type"`
			Count     int       `json:"count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Data) != 1 {
		t.Fatalf("rows = %d, want 1", len(env.Data))
	}
	if env.Data[0].EventType != "proxy_allowlist_reload" || env.Data[0].Count != 5 {
		t.Errorf("row = %+v; want (proxy_allowlist_reload, 5)", env.Data[0])
	}
}
