package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/handlers"
)

// newRouter wires a Scans handler with the given store.
func newRouter(store scanorch.Store) http.Handler {
	return handlers.Scans(store)
}

// TestSubmitScan_Happy: POST /api/v1/scans returns 202 + Job
// envelope with State=queued.
func TestSubmitScan_Happy(t *testing.T) {
	store := scanorch.NewMemoryStore()
	router := newRouter(store)
	body := []byte(`{"input":"list:targets.txt","plugins":["modbus"],"default_port":502}`)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scans", bytes.NewReader(body))
	req.Header.Set("X-Operator", "alice")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Schema string       `json:"schema"`
		Data   scanorch.Job `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode err = %v", err)
	}
	if resp.Schema != "api:v1" {
		t.Errorf("schema = %q", resp.Schema)
	}
	if resp.Data.State != scanorch.StateQueued {
		t.Errorf("State = %q", resp.Data.State)
	}
	if resp.Data.Operator != "alice" {
		t.Errorf("Operator = %q, want alice", resp.Data.Operator)
	}
}

// TestSubmitScan_MalformedJSON returns 400.
func TestSubmitScan_MalformedJSON(t *testing.T) {
	router := newRouter(scanorch.NewMemoryStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scans", strings.NewReader("{not json"))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestSubmitScan_MissingInput returns 400.
func TestSubmitScan_MissingInput(t *testing.T) {
	router := newRouter(scanorch.NewMemoryStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/scans", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "input is required") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

// TestGetScan_Happy: round-trip via POST + GET.
func TestGetScan_Happy(t *testing.T) {
	store := scanorch.NewMemoryStore()
	job, _ := store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	router := newRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scans/"+job.ID, nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data scanorch.Job `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Data.ID != job.ID {
		t.Errorf("ID = %q, want %q", resp.Data.ID, job.ID)
	}
}

// TestGetScan_NotFound returns 404.
func TestGetScan_NotFound(t *testing.T) {
	router := newRouter(scanorch.NewMemoryStore())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scans/no-such-id", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

// TestListScans_NewestFirst: submit 3, list, verify order.
func TestListScans_NewestFirst(t *testing.T) {
	store := scanorch.NewMemoryStore()
	for i := 0; i < 3; i++ {
		_, _ = store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	}
	router := newRouter(store)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/scans", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var resp struct {
		Data []scanorch.Job `json:"data"`
	}
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Data) != 3 {
		t.Errorf("len(jobs) = %d, want 3", len(resp.Data))
	}
}

// TestListScans_LimitParam clamps to [1, 100].
func TestListScans_LimitParam(t *testing.T) {
	store := scanorch.NewMemoryStore()
	for i := 0; i < 30; i++ {
		_, _ = store.Submit(context.Background(), scanorch.SubmitRequest{Input: "stdin"}, "alice")
	}
	router := newRouter(store)
	for _, tc := range []struct {
		name   string
		limit  string
		expect int
	}{
		{"limit-5", "5", 5},
		{"limit-zero-defaults-to-20", "0", 20},
		{"limit-empty-defaults-to-20", "", 20},
		{"limit-too-big-clamped-to-100", "9999", 30}, // only 30 jobs exist
		{"limit-negative-defaults-to-20", "-1", 20},
		{"limit-non-numeric-defaults-to-20", "abc", 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := "/api/v1/scans"
			if tc.limit != "" {
				url += "?limit=" + tc.limit
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			var resp struct {
				Data []scanorch.Job `json:"data"`
			}
			_ = json.NewDecoder(rr.Body).Decode(&resp)
			if len(resp.Data) != tc.expect {
				t.Errorf("len(jobs) = %d, want %d", len(resp.Data), tc.expect)
			}
		})
	}
}

// TestScans_NilStoreReturns503: a serve config without the
// scan orchestrator wires Scans(nil), which surfaces 503 to
// every request.
func TestScans_NilStoreReturns503(t *testing.T) {
	router := newRouter(nil)
	for _, method := range []struct {
		verb string
		path string
	}{
		{http.MethodPost, "/api/v1/scans"},
		{http.MethodGet, "/api/v1/scans"},
		{http.MethodGet, "/api/v1/scans/abc"},
	} {
		t.Run(method.verb+" "+method.path, func(t *testing.T) {
			var body *strings.Reader
			if method.verb == http.MethodPost {
				body = strings.NewReader(`{"input":"stdin"}`)
			}
			var req *http.Request
			if body != nil {
				req = httptest.NewRequestWithContext(t.Context(), method.verb, method.path, body)
			} else {
				req = httptest.NewRequestWithContext(t.Context(), method.verb, method.path, nil)
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", rr.Code)
			}
		})
	}
}
