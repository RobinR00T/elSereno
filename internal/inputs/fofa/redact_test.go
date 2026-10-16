package fofa_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/fofa"
)

// failingTransport fails every request without opening a socket;
// http.Client.Do still wraps the failure in a *url.Error that quotes the
// whole request URL, as a DNS, refused or TLS failure would.
type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated transport failure")
}

const email, key = "ops@example.com", "s3cr3t-fofa-key"

func searchErr(t *testing.T, baseURL string) error {
	t.Helper()
	c, err := fofa.New(email, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = baseURL
	c.HTTP = &http.Client{Transport: failingTransport{}}
	_, err = c.Search(context.Background(), `protocol="modbus"`, 10)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, leak := range []string{key, email, url.QueryEscape(email)} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error carries %q: %v", leak, err)
		}
	}
	return err
}

// TestTransportErrorsHideTheCredentials: FOFA takes the account e-mail
// and the API key in the query string, and a transport failure returns
// `Get "<URL>": ...`. Until 2026-10-16 both reached the terminal
// (PITF-088).
func TestTransportErrorsHideTheCredentials(t *testing.T) {
	err := searchErr(t, "https://fofa.invalid")
	if !strings.Contains(err.Error(), "key=REDACTED") || !strings.Contains(err.Error(), "email=REDACTED") {
		t.Fatalf("error lost the redacted URL: %v", err)
	}
}

// TestBadBaseURLHidesTheCredentials: a malformed base URL fails in
// NewRequestWithContext, whose error quotes the whole URL too.
func TestBadBaseURLHidesTheCredentials(t *testing.T) {
	_ = searchErr(t, "http://[bad")
}
