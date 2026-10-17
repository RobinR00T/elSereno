package opcuahttps

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestProbeGetEndpoints_DoesNotFollowRedirects: the probe reads the
// target's answer and never follows a redirect elsewhere (PITF-095).
func TestProbeGetEndpoints_DoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		elsewhere.Add(1)
	}))
	defer other.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusTemporaryRedirect)
	}))
	defer target.Close()

	if _, err := probeGetEndpoints(context.Background(), target.URL+"/", "opc.https://x", 5*time.Second); err == nil {
		t.Fatal("a redirect was read as an endpoint list")
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the redirect target got %d requests", n)
	}
}
