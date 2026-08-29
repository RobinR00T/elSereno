package shodan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"local/elsereno/internal/inputs/shodan"
)

func TestNewRejectsEmptyKey(t *testing.T) {
	t.Parallel()
	_, err := shodan.New("", 0)
	if !errors.Is(err, shodan.ErrNoAPIKey) {
		t.Fatalf("got %v, want ErrNoAPIKey", err)
	}
}

func TestSearchParsesHits(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			http.Error(w, "no key", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{
			"total": 3,
			"matches": [
				{"ip_str":"10.0.0.1","port":502,"asn":"AS12345"},
				{"ip_str":"2001:db8::1","port":102},
				{"ip_str":"not-an-ip","port":22},
				{"ip_str":"10.0.0.2","port":99999}
			]
		}`)
	}))
	defer srv.Close()

	c, err := shodan.New("dummy", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.BaseURL = srv.URL

	targets, err := c.Search(context.Background(), "port:502", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	// 2 valid hits (not-an-ip and invalid port dropped).
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if targets[0].Address.String() != "10.0.0.1" || int(targets[0].Port) != 502 {
		t.Fatalf("unexpected hit[0]: %+v", targets[0])
	}
}

// TestSearchPagedTerminatesOnUnparseablePages: a provider that keeps
// returning full pages (raw == perPage) whose rows are all unparseable
// advances neither len(out) nor the raw<perPage / raw==0 break
// conditions. The page cap must stop the loop instead of spinning
// forever.
func TestSearchPagedTerminatesOnUnparseablePages(t *testing.T) {
	t.Parallel()
	var reqs int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&reqs, 1)
		var b strings.Builder
		b.WriteString(`{"total":100000,"matches":[`)
		for i := 0; i < 100; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"ip_str":"not-an-ip","port":22}`)
		}
		b.WriteString(`]}`)
		fmt.Fprint(w, b.String())
	}))
	defer srv.Close()
	c, _ := shodan.New("k", 0)
	c.BaseURL = srv.URL

	targets, err := c.SearchPaged(context.Background(), "q", 100)
	if err != nil {
		t.Fatalf("SearchPaged: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("got %d targets, want 0 (all rows unparseable)", len(targets))
	}
	// maxPages = 100/100 + 64 = 65, so the loop is bounded.
	if n := atomic.LoadInt32(&reqs); n == 0 || n > 66 {
		t.Fatalf("request count = %d, want in (0, 66] (page cap)", n)
	}
}

func TestSearchNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := shodan.New("k", 0)
	c.BaseURL = srv.URL
	_, err := c.Search(context.Background(), "q", 10)
	if err == nil {
		t.Fatal("expected error on non-200")
	}
}
