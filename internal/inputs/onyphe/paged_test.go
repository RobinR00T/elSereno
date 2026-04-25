package onyphe_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"local/elsereno/internal/inputs/onyphe"
)

// TestSearchPaged_AccumulatesAcrossPages — server returns 50
// per page; loop iterates until totalLimit hit.
func TestSearchPaged_AccumulatesAcrossPages(t *testing.T) {
	var pages int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&pages, 1)
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		var matches []onyphe.SearchMatch
		if page <= 4 { // 4 pages × 50 = 200 total
			for i := 0; i < 50; i++ {
				matches = append(matches, onyphe.SearchMatch{
					IP:   fmt.Sprintf("10.0.%d.%d", page, i+1),
					Port: "443",
				})
			}
		}
		_ = json.NewEncoder(w).Encode(onyphe.SearchResponse{Status: "ok", Results: matches})
	}))
	defer srv.Close()

	c, err := onyphe.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 200)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 200 {
		t.Errorf("len=%d, want 200", len(hits))
	}
	if got := atomic.LoadInt64(&pages); got < 4 {
		t.Errorf("server pages=%d, want ≥ 4", got)
	}
}
