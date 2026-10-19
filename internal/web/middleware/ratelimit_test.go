package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/web/middleware"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func do(h http.Handler, remote, authz, operator, path string) int {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1"+path, nil)
	r.RemoteAddr = remote
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	if operator != "" {
		r.Header.Set("X-Operator", operator)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// TestRateLimiter_PerIP: a non-loopback client over its per-minute cap
// gets 429; loopback is exempt (PITF-100).
func TestRateLimiter_PerIP(t *testing.T) {
	h := middleware.NewRateLimiter(3, 0).Wrap(okHandler())
	remote := "10.0.0.9:5555"
	for i := 0; i < 3; i++ {
		if code := do(h, remote, "", "", "/api/v1/scans"); code != http.StatusOK {
			t.Fatalf("request %d: code %d, want 200", i, code)
		}
	}
	if code := do(h, remote, "", "", "/api/v1/scans"); code != http.StatusTooManyRequests {
		t.Fatalf("over cap: code %d, want 429", code)
	}
	// A different IP has its own bucket.
	if code := do(h, "10.0.0.10:5555", "", "", "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("other IP: code %d, want 200", code)
	}
	// Loopback is exempt from the per-IP cap.
	for i := 0; i < 10; i++ {
		if code := do(h, "127.0.0.1:5555", "", "", "/api/v1/scans"); code != http.StatusOK {
			t.Fatalf("loopback request %d throttled: %d", i, code)
		}
	}
}

// TestRateLimiter_PerToken: the per-token cap applies even to loopback.
func TestRateLimiter_PerToken(t *testing.T) {
	h := middleware.NewRateLimiter(0, 2).Wrap(okHandler())
	for i := 0; i < 2; i++ {
		if code := do(h, "127.0.0.1:1", "Bearer tok-abc", "", "/api/v1/scans"); code != http.StatusOK {
			t.Fatalf("token request %d: %d", i, code)
		}
	}
	if code := do(h, "127.0.0.1:1", "Bearer tok-abc", "", "/api/v1/scans"); code != http.StatusTooManyRequests {
		t.Fatalf("token over cap: %d, want 429", code)
	}
	if code := do(h, "127.0.0.1:1", "Bearer tok-other", "", "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("other token: %d, want 200", code)
	}
	// X-Operator keys the token limit (in any auth mode).
	ho := middleware.NewRateLimiter(0, 1).Wrap(okHandler())
	if code := do(ho, "127.0.0.1:1", "", "alice", "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("operator first: %d", code)
	}
	if code := do(ho, "127.0.0.1:1", "", "alice", "/api/v1/scans"); code != http.StatusTooManyRequests {
		t.Fatalf("operator over cap: %d, want 429", code)
	}
}

// TestRateLimiter_HealthExempt: /healthz and /readyz are never limited.
func TestRateLimiter_HealthExempt(t *testing.T) {
	h := middleware.NewRateLimiter(1, 0).Wrap(okHandler())
	for _, p := range []string{"/healthz", "/readyz"} {
		for i := 0; i < 5; i++ {
			if code := do(h, "10.0.0.9:1", "", "", p); code != http.StatusOK {
				t.Fatalf("%s request %d: %d, want 200", p, i, code)
			}
		}
	}
}

// TestRateLimiter_Disabled: both caps zero, or a nil limiter, is a
// pass-through.
func TestRateLimiter_Disabled(t *testing.T) {
	h := middleware.NewRateLimiter(0, 0).Wrap(okHandler())
	for i := 0; i < 50; i++ {
		if code := do(h, "10.0.0.9:1", "", "", "/api/v1/scans"); code != http.StatusOK {
			t.Fatalf("disabled limiter throttled at %d", i)
		}
	}
	var nilRL *middleware.RateLimiter
	if code := do(nilRL.Wrap(okHandler()), "10.0.0.9:1", "", "", "/x"); code != http.StatusOK {
		t.Fatalf("nil limiter: %d", code)
	}
}

// TestRateLimiter_Combined: with both caps set, a non-loopback caller
// with a token is refused by whichever bucket runs out first, and a
// refusal by the IP bucket does not spend the token bucket.
func TestRateLimiter_Combined(t *testing.T) {
	h := middleware.NewRateLimiter(2, 3).Wrap(okHandler())
	for i := 0; i < 2; i++ {
		if code := do(h, "10.0.0.9:1", "Bearer tok-a", "", "/api/v1/scans"); code != http.StatusOK {
			t.Fatalf("request %d: %d, want 200", i, code)
		}
	}
	// IP bucket empty (2/2), token bucket has 1 left: refused by IP.
	if code := do(h, "10.0.0.9:1", "Bearer tok-a", "", "/api/v1/scans"); code != http.StatusTooManyRequests {
		t.Fatalf("IP over cap: %d, want 429", code)
	}
	// The IP refusal handed the token back: the same token from a
	// fresh IP still has exactly 1 request left.
	if code := do(h, "10.0.0.10:1", "Bearer tok-a", "", "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("token after IP refusal: %d, want 200", code)
	}
	if code := do(h, "10.0.0.11:1", "Bearer tok-a", "", "/api/v1/scans"); code != http.StatusTooManyRequests {
		t.Fatalf("token over cap: %d, want 429", code)
	}
	// Loopback with the same token is still bound by the token cap.
	if code := do(h, "127.0.0.1:1", "Bearer tok-a", "", "/api/v1/scans"); code != http.StatusTooManyRequests {
		t.Fatalf("loopback token over cap: %d, want 429", code)
	}
}

// TestRateLimiter_RetryAfter: a 429 carries Retry-After: 60.
func TestRateLimiter_RetryAfter(t *testing.T) {
	h := middleware.NewRateLimiter(1, 0).Wrap(okHandler())
	if code := do(h, "10.0.0.9:1", "", "", "/api/v1/scans"); code != http.StatusOK {
		t.Fatalf("first: %d", code)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/scans", nil)
	r.RemoteAddr = "10.0.0.9:1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second: %d, want 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60", got)
	}
}
