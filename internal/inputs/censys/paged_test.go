package censys_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"local/elsereno/internal/inputs/censys"
)

// TestSearchPaged_FollowsCursor — Censys uses cursor pagination.
// Server returns 100 hits + "next" cursor; client follows it for
// up to 3 hops, then "next":"" terminates.
func TestSearchPaged_FollowsCursor(t *testing.T) {
	var pages int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&pages, 1)
		cursor := r.URL.Query().Get("cursor")
		var resp censys.SearchResponseV2
		// pages 1..3 return 100 hits + a next cursor; page 4
		// (cursor=last) returns 0 + empty next.
		switch cursor {
		case "":
			for i := 0; i < 100; i++ {
				resp.Result.Hits = append(resp.Result.Hits, censys.HitV2{
					IP:       fmt.Sprintf("10.0.1.%d", i+1),
					Services: []censys.ServiceV2{{Port: 80}},
				})
			}
			resp.Result.Links.Next = "page2"
		case "page2":
			for i := 0; i < 100; i++ {
				resp.Result.Hits = append(resp.Result.Hits, censys.HitV2{
					IP:       fmt.Sprintf("10.0.2.%d", i+1),
					Services: []censys.ServiceV2{{Port: 80}},
				})
			}
			resp.Result.Links.Next = "page3"
		case "page3":
			for i := 0; i < 100; i++ {
				resp.Result.Hits = append(resp.Result.Hits, censys.HitV2{
					IP:       fmt.Sprintf("10.0.3.%d", i+1),
					Services: []censys.ServiceV2{{Port: 80}},
				})
			}
			resp.Result.Links.Next = "" // terminator
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c, err := censys.New("id", "secret", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 1000)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 300 {
		t.Errorf("len=%d, want 300 (3 cursor hops × 100)", len(hits))
	}
	if got := atomic.LoadInt64(&pages); got != 3 {
		t.Errorf("server pages=%d, want 3", got)
	}
}

// TestSearchPaged_StopsAtTotalLimit — totalLimit=150 caps at 150
// even when more cursor pages remain.
func TestSearchPaged_StopsAtTotalLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var resp censys.SearchResponseV2
		for i := 0; i < 100; i++ {
			resp.Result.Hits = append(resp.Result.Hits, censys.HitV2{
				IP:       fmt.Sprintf("10.0.0.%d", i+1),
				Services: []censys.ServiceV2{{Port: 80}},
			})
		}
		resp.Result.Links.Next = "always-more" // never empty
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c, err := censys.New("id", "secret", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	hits, err := c.SearchPaged(context.Background(), "any", 150)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(hits) != 150 {
		t.Errorf("len=%d, want 150 (capped)", len(hits))
	}
}
