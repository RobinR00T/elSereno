package zoomeye_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"local/elsereno/internal/inputs/zoomeye"
)

// TestSearchPaged_AccumulatesAcrossPages — server returns 20
// per page; SearchPaged must iterate until totalLimit hit.
func TestSearchPaged_AccumulatesAcrossPages(t *testing.T) {
	var pages int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&pages, 1)
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		var matches []zoomeye.SearchMatch
		if page <= 5 { // 5 pages × 20 = 100 total
			for i := 0; i < 20; i++ {
				matches = append(matches, zoomeye.SearchMatch{
					IP:       fmt.Sprintf("10.0.%d.%d", page, i+1),
					PortInfo: zoomeye.PortInfo{Port: 80},
				})
			}
		}
		_ = json.NewEncoder(w).Encode(zoomeye.SearchResponse{Total: 100, Matches: matches})
	}))
	defer srv.Close()

	c, err := zoomeye.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 100)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 100 {
		t.Errorf("len=%d, want 100", len(hits))
	}
	if got := atomic.LoadInt64(&pages); got < 5 {
		t.Errorf("server pages=%d, want ≥ 5 (paginated 5×20=100)", got)
	}
}

// TestSearchPaged_StopsOnEmpty — page 1 returns 20, page 2 is
// empty → loop exits with 20 hits even though totalLimit is
// 1000.
func TestSearchPaged_StopsOnEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		var matches []zoomeye.SearchMatch
		if page == 1 {
			for i := 0; i < 20; i++ {
				matches = append(matches, zoomeye.SearchMatch{
					IP:       fmt.Sprintf("10.0.0.%d", i+1),
					PortInfo: zoomeye.PortInfo{Port: 80},
				})
			}
		}
		_ = json.NewEncoder(w).Encode(zoomeye.SearchResponse{Total: 20, Matches: matches})
	}))
	defer srv.Close()

	c, err := zoomeye.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 1000)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 20 {
		t.Errorf("len=%d, want 20 (only 1 page available)", len(hits))
	}
}
