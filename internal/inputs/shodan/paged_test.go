package shodan_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"local/elsereno/internal/inputs/shodan"
)

// TestSearchPaged_StopsAtTotalLimit drives the loop with a
// generous totalLimit and a server that returns 100 hits per
// page. Verifies the client stops at totalLimit, not when the
// server runs out.
func TestSearchPaged_StopsAtTotalLimit(t *testing.T) {
	var pageHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&pageHits, 1)
		var matches []shodan.SearchHit
		// Always return 100 — server has infinite hits.
		for i := 0; i < 100; i++ {
			matches = append(matches, shodan.SearchHit{
				IP:   fmt.Sprintf("10.0.0.%d", i+1),
				Port: 80,
			})
		}
		_ = json.NewEncoder(w).Encode(shodan.SearchResponse{Total: 999999, Matches: matches})
	}))
	defer srv.Close()

	c, err := shodan.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 250)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 250 {
		t.Errorf("len=%d, want 250", len(hits))
	}
	// 250 / 100 = 2 full + 1 partial = 3 pages.
	if got := atomic.LoadInt64(&pageHits); got != 3 {
		t.Errorf("server hits=%d, want 3 (250/100=2.5)", got)
	}
}

// TestSearchPaged_StopsOnEmptyPage drives the loop against a
// server that returns 100 on page 1 + 0 on page 2. Verifies
// the loop stops when the server says "no more".
func TestSearchPaged_StopsOnEmptyPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		var matches []shodan.SearchHit
		if page == 1 {
			for i := 0; i < 100; i++ {
				matches = append(matches, shodan.SearchHit{
					IP:   fmt.Sprintf("10.0.0.%d", i+1),
					Port: 80,
				})
			}
		}
		// page 2 → empty
		_ = json.NewEncoder(w).Encode(shodan.SearchResponse{Total: 100, Matches: matches})
	}))
	defer srv.Close()

	c, err := shodan.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 1000)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 100 {
		t.Errorf("len=%d, want 100 (server only has 1 page)", len(hits))
	}
}

// TestSearchPaged_ZeroLimitDefaultsTo100 — totalLimit ≤ 0
// degrades to 100, matching Search's single-shot behaviour.
func TestSearchPaged_ZeroLimitDefaultsTo100(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var matches []shodan.SearchHit
		for i := 0; i < 100; i++ {
			matches = append(matches, shodan.SearchHit{
				IP:   fmt.Sprintf("10.0.0.%d", i+1),
				Port: 80,
			})
		}
		_ = json.NewEncoder(w).Encode(shodan.SearchResponse{Total: 999, Matches: matches})
	}))
	defer srv.Close()

	c, err := shodan.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 0)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 100 {
		t.Errorf("len=%d, want 100 (default cap)", len(hits))
	}
}
