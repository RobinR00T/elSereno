package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestNew_RefusesHostChange: a redirect to another host is refused, so
// a provider's API key never reaches it; a same-host redirect is
// followed (PITF-097).
func TestNew_RefusesHostChange(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		if r.Header.Get("X-Key") != "" {
			t.Errorf("API key reached the redirect host")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	var sameHit atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusFound)
	})
	mux.HandleFunc("/hop", func(w http.ResponseWriter, r *http.Request) {
		if sameHit.Add(1) == 1 {
			http.Redirect(w, r, "/hop2", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/hop2", func(w http.ResponseWriter, _ *http.Request) { sameHit.Add(1); w.WriteHeader(http.StatusOK) })
	origin := httptest.NewServer(mux)
	defer origin.Close()

	c := New(5 * time.Second)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+"/start", nil)
	req.Header.Set("X-Key", "secret")
	if resp, err := c.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("cross-host redirect was followed")
	}
	if otherHits.Load() != 0 {
		t.Fatalf("the other host got %d requests", otherHits.Load())
	}

	hreq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+"/hop", nil)
	resp, err := c.Do(hreq)
	if err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || sameHit.Load() != 2 {
		t.Fatalf("same-host redirect not followed: status %d, hits %d", resp.StatusCode, sameHit.Load())
	}
}

// TestNew_RefusesSchemeDowngrade: a same-host redirect from https to
// http is refused, so the key never travels in clear (PITF-097 audit).
func TestNew_RefusesSchemeDowngrade(t *testing.T) {
	c := New(5 * time.Second)
	via := []*http.Request{mustReq(t, "https://api.example:443/x")}
	req := mustReq(t, "http://api.example:443/x")
	if err := c.CheckRedirect(req, via); err == nil {
		t.Fatal("a downgrade to http on the same host was allowed")
	}
}

// TestNew_StopsAtHopCap: a same-authority redirect loop stops at the
// 10-hop cap with the last response, not an error.
func TestNew_StopsAtHopCap(t *testing.T) {
	c := New(5 * time.Second)
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = mustReq(t, "https://api.example/x")
	}
	req := mustReq(t, "https://api.example/x")
	if err := c.CheckRedirect(req, via); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("at the hop cap: err = %v, want ErrUseLastResponse", err)
	}
}

// TestNew_FirstRequestAllowed: the first request (empty via) is never
// blocked.
func TestNew_FirstRequestAllowed(t *testing.T) {
	if err := New(time.Second).CheckRedirect(mustReq(t, "https://api.example/x"), nil); err != nil {
		t.Fatalf("first request blocked: %v", err)
	}
}

func mustReq(t *testing.T, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
