//go:build offensive

package harvest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestHTTPBasic_DoesNotFollowRedirects: a device that answers with a
// redirect cannot send the probe (or its default credentials) to
// another address: the redirect target gets no request (PITF-095).
func TestHTTPBasic_DoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhere.Add(1)
		w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusFound)
	}))
	defer target.Close()

	_, err := NewHTTPBasic().Probe(context.Background(), strings.TrimPrefix(target.URL, "http://"), DefaultCredentials())
	if !errors.Is(err, ErrNoHit) {
		t.Fatalf("err = %v, want ErrNoHit (a redirect is not a Basic challenge)", err)
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the redirect target got %d requests", n)
	}
}
