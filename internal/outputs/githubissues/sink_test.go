package githubissues_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/githubissues"
)

func sampleFinding() core.Finding {
	return core.Finding{
		ID:       "f-001",
		RunID:    "r-9",
		Protocol: "modbus",
		Severity: core.SeverityHigh,
		Score:    75,
		Factors:  map[string]int{"protocol_risk": 85, "exposure": 80},
	}
}

func TestSink_SendHappyPath(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":42,"id":1,"node_id":"n"}`))
	}))
	t.Cleanup(srv.Close)

	s := githubissues.New(githubissues.Config{
		BaseURL: srv.URL,
		Owner:   "acme",
		Repo:    "ot-audits",
		Token:   []byte("ghp_xxx"),
	})
	num, err := s.Send(context.Background(), sampleFinding(), "10.0.0.1:502")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if num != 42 {
		t.Fatalf("issue number = %d", num)
	}
	if gotPath != "/repos/acme/ot-audits/issues" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer ghp_xxx" {
		t.Fatalf("auth = %q", gotAuth)
	}
	var parsed map[string]any
	_ = json.Unmarshal(gotBody, &parsed)
	title, _ := parsed["title"].(string)
	if !strings.Contains(title, "modbus") || !strings.Contains(title, "score 75") {
		t.Fatalf("title = %q", title)
	}
	body, _ := parsed["body"].(string)
	if !strings.Contains(body, "protocol_risk") || !strings.Contains(body, "| 85 |") {
		t.Fatalf("body factor table missing: %s", body)
	}
	labels, _ := parsed["labels"].([]any)
	seen := map[string]bool{}
	for _, l := range labels {
		if s, ok := l.(string); ok {
			seen[s] = true
		}
	}
	for _, want := range []string{"elsereno", "severity/high", "protocol/modbus", "run/r-9"} {
		if !seen[want] {
			t.Errorf("missing label %q in %+v", want, labels)
		}
	}
}

func TestSink_Non2xxError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Validation Failed"}`))
	}))
	t.Cleanup(srv.Close)
	s := githubissues.New(githubissues.Config{
		BaseURL: srv.URL,
		Owner:   "a", Repo: "b",
		Token: []byte("t"),
	})
	_, err := s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, githubissues.ErrNon2xx) {
		t.Fatalf("want ErrNon2xx, got %v", err)
	}
}

func TestSink_MissingConfig(t *testing.T) {
	s := githubissues.New(githubissues.Config{})
	_, err := s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, githubissues.ErrEmptyRepo) {
		t.Fatalf("want ErrEmptyRepo, got %v", err)
	}
	s = githubissues.New(githubissues.Config{Owner: "a", Repo: "b"})
	_, err = s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, githubissues.ErrEmptyToken) {
		t.Fatalf("want ErrEmptyToken, got %v", err)
	}
}

func TestSink_GHESBaseURLOverride(t *testing.T) {
	// Verify that BaseURL stays intact if supplied (trim trailing slash).
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"number":7}`))
	}))
	t.Cleanup(srv.Close)
	s := githubissues.New(githubissues.Config{
		BaseURL: srv.URL + "/",
		Owner:   "o", Repo: "r", Token: []byte("t"),
	})
	_, err := s.Send(context.Background(), sampleFinding(), "x")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/repos/o/r/issues" {
		t.Fatalf("path = %q", gotPath)
	}
}
