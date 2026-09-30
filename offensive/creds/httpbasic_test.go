//go:build offensive

package creds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckHTTPBasicDefaults_AcceptsKnownDefault(t *testing.T) {
	// A device UI that requires Basic auth and accepts admin/admin.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "admin" && p == "admin" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="device"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rep, err := CheckHTTPBasicDefaults(ctx, ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("CheckHTTPBasicDefaults: %v", err)
	}
	if !rep.RequiresAuth {
		t.Fatalf("RequiresAuth = false; baseline status %d", rep.BaselineStatus)
	}
	if rep.Tested == 0 {
		t.Fatal("Tested = 0; expected the defaults to be tried")
	}
	found := false
	for _, c := range rep.Accepted {
		if c.User == "admin" && c.Pass == "admin" {
			found = true
		}
	}
	if !found {
		t.Errorf("admin/admin not reported accepted; accepted = %+v", rep.Accepted)
	}
}

func TestCheckHTTPBasicDefaults_NoAuthGate(t *testing.T) {
	// A page that does not gate on Basic auth must never report accepted creds.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rep, err := CheckHTTPBasicDefaults(ctx, ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("CheckHTTPBasicDefaults: %v", err)
	}
	if rep.RequiresAuth {
		t.Errorf("RequiresAuth = true for an open page (status %d)", rep.BaselineStatus)
	}
	if rep.Tested != 0 || len(rep.Accepted) != 0 {
		t.Errorf("open page must not test or accept creds: tested=%d accepted=%d", rep.Tested, len(rep.Accepted))
	}
}

func TestCheckHTTPBasicDefaults_WrongCreds(t *testing.T) {
	// Requires auth but accepts none of the published defaults.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if ok && u == "s3cure" && p == "Xk9!zq" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rep, err := CheckHTTPBasicDefaults(ctx, ts.Client(), ts.URL)
	if err != nil {
		t.Fatalf("CheckHTTPBasicDefaults: %v", err)
	}
	if !rep.RequiresAuth {
		t.Fatal("RequiresAuth = false; expected an auth gate")
	}
	if len(rep.Accepted) != 0 {
		t.Errorf("expected no accepted defaults, got %+v", rep.Accepted)
	}
}
