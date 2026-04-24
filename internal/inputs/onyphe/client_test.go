package onyphe_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/onyphe"
)

func TestNewRejectsEmptyKey(t *testing.T) {
	t.Parallel()
	_, err := onyphe.New("", 0)
	if !errors.Is(err, onyphe.ErrNoAPIKey) {
		t.Fatalf("got %v, want ErrNoAPIKey", err)
	}
}

func TestSearchParsesMatches(t *testing.T) {
	t.Parallel()
	var sawAuth, sawPath, sawPage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		sawPath = r.URL.Path
		sawPage = r.URL.Query().Get("page")
		if !strings.HasPrefix(sawAuth, "bearer ") {
			http.Error(w, "missing bearer", http.StatusUnauthorized) //nolint:misspell // RFC 6750
			return
		}
		fmt.Fprint(w, `{
			"status": "ok",
			"error": 0,
			"count": 4,
			"total": 4,
			"results": [
				{"ip": "10.0.0.1", "port": "502"},
				{"ip": "2001:db8::1", "port": "102"},
				{"ip": "not-an-ip", "port": "22"},
				{"ip": "10.0.0.2", "port": "not-a-number"}
			]
		}`)
	}))
	defer srv.Close()

	c, err := onyphe.New("test-key-abc", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.BaseURL = srv.URL

	targets, err := c.Search(context.Background(), `category:datascan product:freepbx`, 1)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	// Two valid rows (IPv4 + IPv6); bad-IP and bad-port dropped.
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Address.String() != "10.0.0.1" || int(targets[0].Port) != 502 {
		t.Fatalf("unexpected hit[0]: %+v", targets[0])
	}
	if sawAuth != "bearer test-key-abc" {
		t.Errorf("Authorization header = %q, want %q", sawAuth, "bearer test-key-abc")
	}
	// Query is URL-encoded in the path segment.
	if !strings.Contains(sawPath, "/api/v2/search/") {
		t.Errorf("path = %q, want /api/v2/search/...", sawPath)
	}
	if !strings.Contains(sawPath, "category%3Adatascan") && !strings.Contains(sawPath, "category:datascan") {
		// Either PathEscape-encoded or literal — both are valid
		// depending on Go version; just confirm the content is
		// reachable.
		t.Errorf("path %q did not include query payload", sawPath)
	}
	if sawPage != "1" {
		t.Errorf("page=%q, want 1", sawPage)
	}
}

func TestSearchDefaultsPage(t *testing.T) {
	t.Parallel()
	var sawPage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPage = r.URL.Query().Get("page")
		fmt.Fprint(w, `{"status":"ok","error":0,"results":[]}`)
	}))
	defer srv.Close()
	c, _ := onyphe.New("k", 0)
	c.BaseURL = srv.URL
	if _, err := c.Search(context.Background(), "q", 0); err != nil {
		t.Fatal(err)
	}
	if sawPage != "1" {
		t.Fatalf("default page=%q, want 1", sawPage)
	}
}

func TestSearchAPIError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"nok","error":3,"text":"Authentication failed"}`) //nolint:misspell // RFC 6750
	}))
	defer srv.Close()
	c, _ := onyphe.New("k", 0)
	c.BaseURL = srv.URL
	_, err := c.Search(context.Background(), "q", 1)
	if err == nil {
		t.Fatal("expected API error")
	}
	if !strings.Contains(err.Error(), "API error 3") {
		t.Errorf("error should quote code 3: %v", err)
	}
}

func TestSearchNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limit", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := onyphe.New("k", 0)
	c.BaseURL = srv.URL
	_, err := c.Search(context.Background(), "q", 1)
	if err == nil {
		t.Fatal("expected error on non-200")
	}
}
