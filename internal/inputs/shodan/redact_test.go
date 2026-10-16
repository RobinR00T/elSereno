package shodan_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/shodan"
)

// failingTransport fails every request without opening a socket;
// http.Client.Do still wraps the failure in a *url.Error that quotes the
// whole request URL, as a DNS, refused or TLS failure would.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated transport failure")
}

const key = "s3cr3t-shodan-key"

func newClient(t *testing.T, baseURL string) *shodan.Client {
	t.Helper()
	c, err := shodan.New(key, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = baseURL
	c.HTTP = &http.Client{Transport: failingTransport{}}
	return c
}

func requireNoKey(t *testing.T, name string, err error, wantRedacted bool) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want an error", name)
	}
	if strings.Contains(err.Error(), key) {
		t.Fatalf("%s error carries the API key: %v", name, err)
	}
	if wantRedacted && !strings.Contains(err.Error(), "key=REDACTED") {
		t.Fatalf("%s error lost the redacted URL: %v", name, err)
	}
}

// TestTransportErrorsHideTheKey: Shodan takes the API key in the query
// string, and a transport failure returns `Get "<URL>": ...`. Until
// 2026-10-16 that URL, key included, reached the terminal (PITF-088).
func TestTransportErrorsHideTheKey(t *testing.T) {
	c := newClient(t, "https://api.shodan.invalid")
	ctx := context.Background()
	_, err := c.Search(ctx, "port:502", 10)
	requireNoKey(t, "Search", err, true)
	_, err = c.Host(ctx, "192.0.2.1", false)
	requireNoKey(t, "Host", err, true)
}

// TestBadBaseURLHidesTheKey: a malformed base URL fails in
// NewRequestWithContext, whose error quotes the whole URL too
// (`parse "<URL>": ...`).
func TestBadBaseURLHidesTheKey(t *testing.T) {
	c := newClient(t, "http://[bad")
	ctx := context.Background()
	_, err := c.Search(ctx, "port:502", 10)
	requireNoKey(t, "Search", err, false)
	_, err = c.Host(ctx, "192.0.2.1", false)
	requireNoKey(t, "Host", err, false)
}
