package zoomeye_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/inputs/zoomeye"
)

func TestNewRejectsEmptyKey(t *testing.T) {
	t.Parallel()
	_, err := zoomeye.New("", 0)
	if !errors.Is(err, zoomeye.ErrNoAPIKey) {
		t.Fatalf("got %v, want ErrNoAPIKey", err)
	}
}

func TestSearchParsesMatches(t *testing.T) {
	t.Parallel()
	var sawHeader string
	var sawQuery string
	var sawPage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("API-KEY")
		sawQuery = r.URL.Query().Get("query")
		sawPage = r.URL.Query().Get("page")
		if sawHeader == "" {
			http.Error(w, "missing API-KEY", http.StatusUnauthorized) //nolint:misspell // RFC 7235 canonical spelling
			return
		}
		fmt.Fprint(w, `{
			"total": 4,
			"matches": [
				{"ip": "10.0.0.1", "portinfo": {"port": 502}},
				{"ip": "2001:db8::1", "portinfo": {"port": 102}},
				{"ip": "not-an-ip", "portinfo": {"port": 22}},
				{"ip": "10.0.0.2", "portinfo": {"port": 99999}}
			]
		}`)
	}))
	defer srv.Close()

	c, err := zoomeye.New("dummy-key", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.BaseURL = srv.URL

	targets, err := c.Search(context.Background(), `app:"Asterisk"`, 1)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Address.String() != "10.0.0.1" || int(targets[0].Port) != 502 {
		t.Fatalf("unexpected hit[0]: %+v", targets[0])
	}
	// Authentication lives in the header, not the URL.
	if sawHeader != "dummy-key" {
		t.Errorf("API-KEY header = %q, want dummy-key", sawHeader)
	}
	if sawQuery != `app:"Asterisk"` {
		t.Errorf("query param = %q, want %q", sawQuery, `app:"Asterisk"`)
	}
	if sawPage != "1" {
		t.Errorf("page param = %q, want 1", sawPage)
	}
}

func TestSearchDefaultsPage(t *testing.T) {
	t.Parallel()
	var sawPage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPage = r.URL.Query().Get("page")
		fmt.Fprint(w, `{"total":0,"matches":[]}`)
	}))
	defer srv.Close()
	c, _ := zoomeye.New("k", 0)
	c.BaseURL = srv.URL
	if _, err := c.Search(context.Background(), "q", 0); err != nil {
		t.Fatal(err)
	}
	if sawPage != "1" {
		t.Fatalf("default page = %q, want 1", sawPage)
	}
}

func TestSearchNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no credits", http.StatusPaymentRequired)
	}))
	defer srv.Close()
	c, _ := zoomeye.New("k", 0)
	c.BaseURL = srv.URL
	_, err := c.Search(context.Background(), "q", 1)
	if err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestSearchEmptyMatches(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"total":0,"matches":[]}`)
	}))
	defer srv.Close()
	c, _ := zoomeye.New("k", 0)
	c.BaseURL = srv.URL
	got, err := c.Search(context.Background(), "q", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 targets on empty matches, got %d", len(got))
	}
}
