package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/web/auth"
)

// TestScopeIdempotencyKey_NamespacesByOperatorAndRoute locks the MEDIO-4
// fix: the cache key is namespaced by operator identity and request
// method+path, so the same client-chosen Idempotency-Key cannot replay
// or suppress another operator's (or another endpoint's) request.
func TestScopeIdempotencyKey_NamespacesByOperatorAndRoute(t *testing.T) {
	mk := func(op, method, path string) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		if op != "" {
			r = r.WithContext(auth.WithOperator(r.Context(), op))
		}
		return r
	}
	const key = "shared-key"
	base := scopeIdempotencyKey(mk("alice", http.MethodPost, "/api/v1/schedules/1/clone"), key)

	cases := []struct {
		name      string
		req       *http.Request
		key       string
		wantMatch bool
	}{
		{"same op+route+key replays", mk("alice", http.MethodPost, "/api/v1/schedules/1/clone"), key, true},
		{"different operator does not collide", mk("bob", http.MethodPost, "/api/v1/schedules/1/clone"), key, false},
		{"different path does not collide", mk("alice", http.MethodPost, "/api/v1/schedules/2/clone"), key, false},
		{"different method does not collide", mk("alice", http.MethodPut, "/api/v1/schedules/1/clone"), key, false},
		{"different key does not collide", mk("alice", http.MethodPost, "/api/v1/schedules/1/clone"), "other", false},
	}
	for _, c := range cases {
		got := scopeIdempotencyKey(c.req, c.key)
		if (got == base) != c.wantMatch {
			t.Errorf("%s: match=%v, want %v", c.name, got == base, c.wantMatch)
		}
	}
}
