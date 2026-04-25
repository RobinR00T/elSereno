package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/inputs/internetdb"
)

// TestReadInternetDBTargets_FileBulk drives readInternetDBTargets
// against a 3-IP file, mocks the InternetDB endpoint, and checks
// the per-IP lookup loop accumulates hits across IPs.
func TestReadInternetDBTargets_FileBulk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path is /<ip>; return one port per IP.
		ip := strings.TrimPrefix(r.URL.Path, "/")
		port := 80
		switch ip {
		case "10.0.0.1":
			port = 80
		case "10.0.0.2":
			port = 443
		case "10.0.0.3":
			port = 22
		}
		_ = json.NewEncoder(w).Encode(internetdb.LookupResponse{
			IP:    ip,
			Ports: []int{port},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	listPath := filepath.Join(dir, "ips.txt")
	body := "# comment\n10.0.0.1\n\n10.0.0.2\n  10.0.0.3  \n"
	if err := os.WriteFile(listPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Driving via the public dispatcher would hard-code the
	// production base URL. We test the lower-level helper that
	// owns the loop, with a Client whose BaseURL points at
	// httptest.
	c := internetdb.New(0)
	c.BaseURL = srv.URL
	ips, err := readInternetDBIPListFromFile(listPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 3 {
		t.Fatalf("ips=%v, want 3 (comment + blank skipped, leading/trailing whitespace trimmed)", ips)
	}
	hits, err := lookupAllInternetDB(context.Background(), c, ips)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 3 {
		t.Fatalf("hits=%v, want 3 (one per IP)", hits)
	}
	wantPorts := map[string]int{
		"10.0.0.1": 80,
		"10.0.0.2": 443,
		"10.0.0.3": 22,
	}
	for _, h := range hits {
		want, ok := wantPorts[h.Address.String()]
		if !ok {
			t.Errorf("unexpected IP in hits: %s", h.Address)
			continue
		}
		if int(h.Port) != want {
			t.Errorf("hit for %s: port=%d, want %d", h.Address, h.Port, want)
		}
	}
}

// TestReadInternetDBIPListFromReader_DropsBlanksAndComments — UI-
// niceness coverage: comments + blank lines + whitespace are
// all handled.
func TestReadInternetDBIPListFromReader_DropsBlanksAndComments(t *testing.T) {
	body := "  # header\n10.0.0.1\n\n# inline comment\n  10.0.0.2  \n\n"
	ips, err := readInternetDBIPListFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("ips=%v, want 2", ips)
	}
	if ips[0] != "10.0.0.1" || ips[1] != "10.0.0.2" {
		t.Errorf("ips=%v, want [10.0.0.1, 10.0.0.2]", ips)
	}
}

// TestReadInternetDBIPListFromReader_EmptyFails — fully empty
// input (only blanks/comments) errors out so operators don't
// silently no-op the bulk lookup.
func TestReadInternetDBIPListFromReader_EmptyFails(t *testing.T) {
	body := "# only comments\n\n# nothing useful\n"
	_, err := readInternetDBIPListFromReader(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected error for empty IP list")
	}
}
