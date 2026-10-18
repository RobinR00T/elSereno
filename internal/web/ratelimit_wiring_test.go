package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/config"
	"local/elsereno/internal/creds"
)

// TestServer_RateLimitWired: the web.rate_limit_per_min_* caps reach
// the handler NewServer builds (PITF-100). A non-loopback caller over
// the per-IP cap gets 429 with Retry-After and the security headers,
// /healthz stays open, and loopback is exempt from the per-IP cap.
func TestServer_RateLimitWired(t *testing.T) {
	vault := creds.New()
	if err := vault.Init(context.Background(), []byte("rate-limit-test")); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	webCfg := config.Defaults().Web
	webCfg.RateLimitPerMinIP = 2
	srv, err := NewServer(Options{Addr: "127.0.0.1:0", Web: webCfg, Vault: vault})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()
	get := func(remote, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		r.Host = "127.0.0.1"
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		if w := get("10.0.0.9:1", "/api/v1/health"); w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled early", i)
		}
	}
	w := get("10.0.0.9:1", "/api/v1/health")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over cap: status %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", w.Header().Get("Retry-After"))
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("429 lacks the security headers")
	}
	if w := get("10.0.0.9:1", "/healthz"); w.Code != http.StatusOK {
		t.Fatalf("/healthz over cap: status %d, want 200", w.Code)
	}
	if w := get("127.0.0.1:1", "/api/v1/health"); w.Code == http.StatusTooManyRequests {
		t.Fatal("loopback throttled by the per-IP cap")
	}
}

// TestServer_RateLimitTokenCapWired: web.rate_limit_per_min_token reaches
// the token bucket, not the IP one (a swap of the two would pass the
// per-IP test above). Loopback is exempt from the IP cap, so only the
// token cap can refuse here.
func TestServer_RateLimitTokenCapWired(t *testing.T) {
	vault := creds.New()
	if err := vault.Init(context.Background(), []byte("rate-limit-token-test")); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	webCfg := config.Defaults().Web
	webCfg.RateLimitPerMinIP = 1000
	webCfg.RateLimitPerMinToken = 1
	srv, err := NewServer(Options{Addr: "127.0.0.1:0", Web: webCfg, Vault: vault})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	h := srv.Handler()
	codes := make([]int, 0, 2)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/health", nil)
		r.Host = "127.0.0.1"
		r.RemoteAddr = "127.0.0.1:1"
		r.Header.Set("X-Operator", "alice")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		codes = append(codes, w.Code)
	}
	if codes[0] == http.StatusTooManyRequests || codes[1] != http.StatusTooManyRequests {
		t.Fatalf("codes = %v, want [not 429, 429] with a token cap of 1", codes)
	}
}
