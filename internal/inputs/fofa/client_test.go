package fofa_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/inputs/fofa"
)

func TestNewRejectsEmptyEmail(t *testing.T) {
	t.Parallel()
	_, err := fofa.New("", "key", 0)
	if !errors.Is(err, fofa.ErrNoCredentials) {
		t.Fatalf("got %v, want ErrNoCredentials", err)
	}
}

func TestNewRejectsEmptyKey(t *testing.T) {
	t.Parallel()
	_, err := fofa.New("user@example.com", "", 0)
	if !errors.Is(err, fofa.ErrNoCredentials) {
		t.Fatalf("got %v, want ErrNoCredentials", err)
	}
}

// TestSearchParsesHits exercises the happy path + edge cases
// (invalid IP, invalid port, short row) in one fixture.
func TestSearchParsesHits(t *testing.T) {
	t.Parallel()
	var sawQbase64 string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Required params present?
		if r.URL.Query().Get("email") == "" || r.URL.Query().Get("key") == "" {
			http.Error(w, "missing creds", http.StatusUnauthorized) //nolint:misspell // RFC 7235 canonical spelling
			return
		}
		sawQbase64 = r.URL.Query().Get("qbase64")
		fmt.Fprint(w, `{
			"error": false,
			"mode": "normal",
			"page": 1,
			"size": 4,
			"results": [
				["10.0.0.1:502", "10.0.0.1", "502"],
				["2001:db8::1:102", "2001:db8::1", "102"],
				["not-an-ip:22", "not-an-ip", "22"],
				["10.0.0.2:99999", "10.0.0.2", "99999"],
				["short-row"]
			]
		}`)
	}))
	defer srv.Close()

	c, err := fofa.New("user@example.com", "dummy-key", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.BaseURL = srv.URL

	targets, err := c.Search(context.Background(), `protocol="iax2"`, 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	// 2 valid hits: the IPv6 one + the IPv4 one. The bad-IP,
	// bad-port and short-row rows are dropped silently.
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Address.String() != "10.0.0.1" || int(targets[0].Port) != 502 {
		t.Fatalf("unexpected hit[0]: %+v", targets[0])
	}
	// qbase64 must decode back to the original query — proves
	// the client base64-encoded what the server expects.
	decoded, err := base64.StdEncoding.DecodeString(sawQbase64)
	if err != nil {
		t.Fatalf("qbase64 decode: %v", err)
	}
	if string(decoded) != `protocol="iax2"` {
		t.Fatalf("qbase64 decoded to %q, want %q", decoded, `protocol="iax2"`)
	}
}

func TestSearchAPIError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"error": true, "errmsg": "820001: [-700] Account Invalid"}`)
	}))
	defer srv.Close()
	c, _ := fofa.New("u@e", "k", 0)
	c.BaseURL = srv.URL
	_, err := c.Search(context.Background(), `q`, 10)
	if !errors.Is(err, fofa.ErrAPIError) {
		t.Fatalf("got %v, want ErrAPIError", err)
	}
}

func TestSearchNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := fofa.New("u@e", "k", 0)
	c.BaseURL = srv.URL
	_, err := c.Search(context.Background(), "q", 10)
	if err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestSearchDefaultsSize(t *testing.T) {
	t.Parallel()
	var sawSize string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSize = r.URL.Query().Get("size")
		fmt.Fprint(w, `{"error":false,"results":[]}`)
	}))
	defer srv.Close()
	c, _ := fofa.New("u@e", "k", 0)
	c.BaseURL = srv.URL
	if _, err := c.Search(context.Background(), "q", 0); err != nil {
		t.Fatal(err)
	}
	if sawSize != "100" {
		t.Fatalf("default size = %q, want 100", sawSize)
	}
}
