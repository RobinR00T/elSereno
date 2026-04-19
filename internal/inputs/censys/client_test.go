package censys_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/inputs/censys"
)

func TestNewRejectsEmptyCreds(t *testing.T) {
	t.Parallel()
	cases := [][2]string{{"", "x"}, {"x", ""}, {"", ""}}
	for _, cc := range cases {
		_, err := censys.New(cc[0], cc[1], 0)
		if !errors.Is(err, censys.ErrNoAPICreds) {
			t.Fatalf("creds=%v got %v, want ErrNoAPICreds", cc, err)
		}
	}
}

func TestSearchParsesHits(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _, ok := r.BasicAuth()
		if !ok || id != "the-id" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"result":{"hits":[
			{"ip":"10.0.0.1","services":[{"port":502},{"port":102}]},
			{"ip":"not-an-ip","services":[{"port":22}]},
			{"ip":"10.0.0.2","services":[{"port":99999}]},
			{"ip":"2001:db8::1","services":[{"port":44818}]}
		]}}`)
	}))
	defer srv.Close()

	c, err := censys.New("the-id", "the-secret", 0)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.BaseURL = srv.URL

	ts, err := c.Search(context.Background(), "services.port:502", 50)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	// Expected: 10.0.0.1:502, 10.0.0.1:102, 2001:db8::1:44818. Skip
	// "not-an-ip" and 99999.
	if len(ts) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(ts), ts)
	}
}
