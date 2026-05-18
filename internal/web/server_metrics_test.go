package web_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/config"
	"local/elsereno/internal/creds"
	"local/elsereno/internal/web"
)

// stubMetricsHandler — synthetic handler so we can confirm
// /metrics is mounted without standing up the full Prometheus
// machinery.
type stubMetricsHandler struct {
	body string
}

func (s *stubMetricsHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, s.body)
}

// TestMetrics_Mounted (v2.60+): when Options.MetricsHandler
// is set, GET /metrics returns the handler's body.
func TestMetrics_Mounted(t *testing.T) {
	vault := creds.New()
	if err := vault.Init(context.Background(), []byte("v2.60-test-pass")); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	srv, err := web.NewServer(web.Options{
		Addr:           "127.0.0.1:0",
		Web:            config.Defaults().Web,
		Vault:          vault,
		MetricsHandler: &stubMetricsHandler{body: "# HELP test 1\n"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Serve via httptest by hitting the internal mux.
	// We rely on Server.Run binding the same handler tree,
	// but here we want a one-shot direct check — re-execute
	// NewServer's chain by issuing a request through the
	// httptest server wrapping srv's Handler.
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/metrics", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "# HELP test 1") {
		t.Errorf("body = %q, want '# HELP test 1' prefix", string(body))
	}
}

// TestMetrics_Unmounted (v2.60+): when MetricsHandler is nil,
// GET /metrics falls through to the dashboard "/" handler
// (so the response is HTML, not the Prometheus expo). The
// concrete assertion: response body doesn't contain Prometheus
// format markers.
func TestMetrics_Unmounted(t *testing.T) {
	vault := creds.New()
	if err := vault.Init(context.Background(), []byte("v2.60-test-pass")); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	srv, err := web.NewServer(web.Options{
		Addr:  "127.0.0.1:0",
		Web:   config.Defaults().Web,
		Vault: vault,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/metrics", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	// Either 404, or "/" catch-all dashboard HTML — both
	// acceptable. What MUST NOT happen: a Prometheus expo
	// body (which would mean the route IS bound and would
	// be a regression).
	if strings.Contains(string(body), "# HELP") || strings.Contains(string(body), "# TYPE") {
		t.Errorf("body looks like Prometheus expo despite nil MetricsHandler: %q",
			string(body)[:min(120, len(body))])
	}
}
