package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/inputs/internetdb"
)

// TestStripIPv6Brackets — the canonical safety invariant of
// v1.14 chunk 3: bracketed IPv6 literals (mirroring the
// --target / --listen host:port convention) get stripped at
// the CLI boundary so the underlying netip.ParseAddr accepts
// them.
func TestStripIPv6Brackets(t *testing.T) {
	cases := map[string]string{
		"[2001:db8::1]":     "2001:db8::1",
		"[::1]":             "::1",
		"[0:0:0:0:0:0:0:1]": "0:0:0:0:0:0:0:1",
		"2001:db8::1":       "2001:db8::1", // no brackets — pass through
		"8.8.8.8":           "8.8.8.8",     // IPv4 — pass through
		"":                  "",
		"[":                 "[",       // unmatched — pass through
		"]":                 "]",       // unmatched — pass through
		"[abc":              "[abc",    // unmatched closing — pass through
		"abc]":              "abc]",    // unmatched opening — pass through
		"[1.2.3.4]":         "1.2.3.4", // brackets-around-IPv4 unusual but tolerated
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			got := stripIPv6Brackets(input)
			if got != want {
				t.Errorf("stripIPv6Brackets(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

// TestReadInternetDBTargets_BracketedIPv6 — operator can pass
// `--input internetdb:[2001:db8::1]` and the gate strips
// brackets before delegating to internetdb.Client.Lookup. Uses
// an httptest server to avoid hitting the real upstream.
func TestReadInternetDBTargets_BracketedIPv6(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path expected: /2001:db8::1 (no brackets).
		if r.URL.Path != "/2001:db8::1" {
			t.Errorf("upstream got path %q, want /2001:db8::1", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(internetdb.LookupResponse{
			IP:    "2001:db8::1",
			Ports: []int{502, 47808},
		})
	}))
	t.Cleanup(srv.Close)

	c := internetdb.New(0)
	c.BaseURL = srv.URL

	// Manually exercise the same path readInternetDBTargets
	// takes for the single-IP form.
	hits, err := c.Lookup(context.Background(), stripIPv6Brackets("[2001:db8::1]"))
	if err != nil {
		t.Fatalf("Lookup error: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("got %d hits, want 2", len(hits))
	}
	if hits[0].Address.String() != "2001:db8::1" {
		t.Errorf("hits[0].Address = %s, want 2001:db8::1", hits[0].Address)
	}
}

// TestReadTargets_InternetDBDispatchWired — the cmd_scan.go
// dispatcher recognises `internetdb:<ip>` (a regression guard
// for the v1.13 chunk 1 oversight where the dispatcher had no
// case for internetdb so --input internetdb:8.8.8.8 errored
// with "unknown input kind"). We don't actually hit the
// upstream — we pass an empty query and check the error path
// proves we routed correctly.
func TestReadTargets_InternetDBDispatchWired(t *testing.T) {
	// Empty query (after the prefix) should produce a routing-
	// specific error, not the dispatcher's "unknown input kind".
	_, err := readTargets(context.Background(), scanOpts{
		inputKind: "internetdb:",
	})
	if err == nil {
		t.Fatal("expected error for empty internetdb query")
	}
	if got := err.Error(); got == "" || (len(got) > 17 && got[:17] == "unknown input kin") {
		t.Errorf("dispatcher rejected internetdb prefix: %v (chunk 3 regression)", err)
	}
}
