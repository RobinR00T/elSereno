package internetdb_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/internetdb"
)

// TestLookup_HappyPath — happy path: server returns 200 with a
// list of ports; client returns one Target per port.
func TestLookup_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/8.8.8.8") {
			t.Errorf("path = %q, want suffix /8.8.8.8", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(internetdb.LookupResponse{
			IP:        "8.8.8.8",
			Ports:     []int{53, 443},
			Hostnames: []string{"dns.google"},
		})
	}))
	defer srv.Close()

	c := internetdb.New(0)
	c.BaseURL = srv.URL

	hits, err := c.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("len=%d, want 2", len(hits))
	}
	if hits[0].Address.String() != "8.8.8.8" {
		t.Errorf("hits[0].Address = %q", hits[0].Address.String())
	}
	if hits[0].Port != 53 {
		t.Errorf("hits[0].Port = %d, want 53", hits[0].Port)
	}
	if hits[1].Port != 443 {
		t.Errorf("hits[1].Port = %d, want 443", hits[1].Port)
	}
}

// TestLookup_NotFoundIsEmpty — 404 from upstream maps to (nil,
// nil), letting the CLI render "no data" cleanly without an
// error.
func TestLookup_NotFoundIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := internetdb.New(0)
	c.BaseURL = srv.URL

	hits, err := c.Lookup(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("404 should not surface as error: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("len=%d, want 0", len(hits))
	}
}

// TestLookup_InvalidIPRejected — non-IP input fails fast with
// ErrInvalidIP. (InternetDB only accepts IPs, not hostnames or
// CIDRs.)
func TestLookup_InvalidIPRejected(t *testing.T) {
	c := internetdb.New(0)
	_, err := c.Lookup(context.Background(), "not-an-ip")
	if !errors.Is(err, internetdb.ErrInvalidIP) {
		t.Errorf("err = %v, want ErrInvalidIP", err)
	}
}

// TestLookup_ServerErrorSurfaces — a 500 response is an error.
func TestLookup_ServerErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := internetdb.New(0)
	c.BaseURL = srv.URL

	_, err := c.Lookup(context.Background(), "8.8.8.8")
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

// TestLookup_DropsInvalidPorts — port 0 / >65535 are dropped
// silently rather than crashing the caller.
func TestLookup_DropsInvalidPorts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(internetdb.LookupResponse{
			IP:    "8.8.8.8",
			Ports: []int{0, 80, 99999},
		})
	}))
	defer srv.Close()

	c := internetdb.New(0)
	c.BaseURL = srv.URL

	hits, err := c.Lookup(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	// Only port 80 survived.
	if len(hits) != 1 || hits[0].Port != 80 {
		t.Errorf("hits = %+v, want one entry on port 80", hits)
	}
}
