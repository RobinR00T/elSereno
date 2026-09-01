package binaryedge_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"local/elsereno/internal/inputs/binaryedge"
)

func TestNew_NoKey(t *testing.T) {
	if _, err := binaryedge.New("", 0); !errors.Is(err, binaryedge.ErrNoAPIKey) {
		t.Fatalf("New(\"\") = %v, want ErrNoAPIKey", err)
	}
}

func TestSearch_ParsesTargetsAndDropsBad(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Key") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if got := r.URL.Query().Get("query"); got != "port:22" {
			t.Errorf("query = %q, want port:22", got)
		}
		_, _ = w.Write([]byte(`{"page":1,"pagesize":20,"total":3,"events":[
			{"target":{"ip":"1.2.3.4","port":22}},
			{"target":{"ip":"not-an-ip","port":80}},
			{"target":{"ip":"5.6.7.8","port":443}}
		]}`))
	}))
	defer srv.Close()

	c, err := binaryedge.New("test-key", 0)
	if err != nil {
		t.Fatal(err)
	}
	c.BaseURL = srv.URL

	got, err := c.Search(context.Background(), "port:22", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 { // the "not-an-ip" event is dropped
		t.Fatalf("got %d targets, want 2", len(got))
	}
	if got[0].Address.String() != "1.2.3.4" || got[1].Address.String() != "5.6.7.8" {
		t.Fatalf("addresses = %s / %s", got[0].Address, got[1].Address)
	}
}

func TestSearch_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c, _ := binaryedge.New("k", 0)
	c.BaseURL = srv.URL
	if _, err := c.Search(context.Background(), "q", 1); err == nil {
		t.Fatal("Search accepted a non-200 status")
	}
}

func TestSearchPaged_AccumulatesAndStops(t *testing.T) {
	// Page 1 returns two events, page 2 returns none -> loop stops.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			_, _ = fmt.Fprint(w, `{"events":[{"target":{"ip":"1.1.1.1","port":80}},{"target":{"ip":"2.2.2.2","port":80}}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"events":[]}`)
	}))
	defer srv.Close()
	c, _ := binaryedge.New("k", 0)
	c.BaseURL = srv.URL
	got, err := c.SearchPaged(context.Background(), "q", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
}
