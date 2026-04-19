package shodan_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
