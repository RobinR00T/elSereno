package fofa_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"local/elsereno/internal/inputs/fofa"
)

// TestSearchPaged_AccumulatesAcrossPages — server returns 100
// per page; loop iterates until totalLimit hit. Verifies the
// `page=N` query param is incremented (FOFA convention is
// 1-indexed).
func TestSearchPaged_AccumulatesAcrossPages(t *testing.T) {
	var pages int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&pages, 1)
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		var rows [][]string
		if page <= 3 {
			for i := 0; i < 100; i++ {
				rows = append(rows, []string{
					fmt.Sprintf("host%d-%d.example.com", page, i),
					fmt.Sprintf("10.0.%d.%d", page, i+1),
					"80",
				})
			}
		}
		_ = json.NewEncoder(w).Encode(fofa.SearchResponse{Results: rows})
	}))
	defer srv.Close()

	c, err := fofa.New("a@b.com", "test-key", 0)
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
	if got := atomic.LoadInt64(&pages); got != 3 {
		t.Errorf("server pages=%d, want 3 (2 full + 1 partial)", got)
	}
}
