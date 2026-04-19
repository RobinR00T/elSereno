package jira_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/jira"
)

func sampleFinding() core.Finding {
	return core.Finding{
		ID:       "f-001",
		RunID:    "r-9",
		Protocol: "modbus",
		Severity: core.SeverityHigh,
		Score:    75,
	}
}

func TestSink_SendHappyPath(t *testing.T) {
	var gotBody []byte
	var gotAuth string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"10042","key":"OT-42"}`))
	}))
	t.Cleanup(srv.Close)

	s := jira.New(jira.Config{
		BaseURL:    srv.URL,
		ProjectKey: "OT",
		Email:      "ops@example.com",
		APIToken:   []byte("secret"),
	})
	key, err := s.Send(context.Background(), sampleFinding(), "10.0.0.1:502")
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if key != "OT-42" {
		t.Fatalf("key = %q", key)
	}
	if gotPath != "/rest/api/3/issue" {
		t.Fatalf("path = %q", gotPath)
	}
	// Basic auth header.
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("ops@example.com:secret"))
	if gotAuth != want {
		t.Fatalf("auth header: got %q", gotAuth)
	}
	// Body sanity: project.key + priority.name + labels.
	var parsed map[string]any
	_ = json.Unmarshal(gotBody, &parsed)
	fields, _ := parsed["fields"].(map[string]any)
	proj, _ := fields["project"].(map[string]any)
	if proj["key"] != "OT" {
		t.Fatalf("project.key = %v", proj["key"])
	}
	pri, _ := fields["priority"].(map[string]any)
	if pri["name"] != "High" {
		t.Fatalf("priority.name = %v", pri["name"])
	}
	labels, _ := fields["labels"].([]any)
	seen := map[string]bool{}
	for _, l := range labels {
		if s, ok := l.(string); ok {
			seen[s] = true
		}
	}
	for _, want := range []string{"elsereno", "severity:high", "protocol:modbus", "run:r-9"} {
		if !seen[want] {
			t.Errorf("missing label %q in %+v", want, labels)
		}
	}
}

func TestSink_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"errors":{"project":"not found"}}`))
	}))
	t.Cleanup(srv.Close)
	s := jira.New(jira.Config{BaseURL: srv.URL, ProjectKey: "OT", Email: "x@y.z", APIToken: []byte("t")})
	_, err := s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, jira.ErrNon2xx) {
		t.Fatalf("want ErrNon2xx, got %v", err)
	}
}

func TestSink_MissingConfig(t *testing.T) {
	s := jira.New(jira.Config{})
	_, err := s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, jira.ErrEmptyBaseURL) {
		t.Fatalf("want ErrEmptyBaseURL, got %v", err)
	}
	s = jira.New(jira.Config{BaseURL: "http://x"})
	_, err = s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, jira.ErrEmptyProject) {
		t.Fatalf("want ErrEmptyProject, got %v", err)
	}
	s = jira.New(jira.Config{BaseURL: "http://x", ProjectKey: "OT"})
	_, err = s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, jira.ErrEmptyAuth) {
		t.Fatalf("want ErrEmptyAuth, got %v", err)
	}
}

func TestSink_PriorityMapping(t *testing.T) {
	for _, tc := range []struct {
		sev  core.Severity
		want string
	}{
		{core.SeverityCritical, "Highest"},
		{core.SeverityHigh, "High"},
		{core.SeverityMedium, "Medium"},
		{core.SeverityLow, "Low"},
		{core.Severity("weird"), "Lowest"},
	} {
		var pri string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			var parsed map[string]any
			_ = json.Unmarshal(b, &parsed)
			fields, _ := parsed["fields"].(map[string]any)
			p, _ := fields["priority"].(map[string]any)
			pri, _ = p["name"].(string)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"key":"X-1"}`))
		}))
		s := jira.New(jira.Config{BaseURL: srv.URL, ProjectKey: "X", Email: "a@b.c", APIToken: []byte("t")})
		f := sampleFinding()
		f.Severity = tc.sev
		_, err := s.Send(context.Background(), f, "10.0.0.1:1")
		if err != nil {
			t.Fatalf("%s: %v", tc.sev, err)
		}
		if pri != tc.want {
			t.Errorf("sev=%s: priority=%q, want %q", tc.sev, pri, tc.want)
		}
		srv.Close()
	}
}

func TestSink_ExtraLabelsAppended(t *testing.T) {
	var gotLabels []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		_ = json.Unmarshal(b, &parsed)
		fields, _ := parsed["fields"].(map[string]any)
		arr, _ := fields["labels"].([]any)
		for _, l := range arr {
			if s, ok := l.(string); ok {
				gotLabels = append(gotLabels, s)
			}
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"X-1"}`))
	}))
	t.Cleanup(srv.Close)
	s := jira.New(jira.Config{
		BaseURL:     srv.URL,
		ProjectKey:  "X",
		Email:       "a@b.c",
		APIToken:    []byte("t"),
		LabelsExtra: []string{"env:prod", "team:ot"},
	})
	_, err := s.Send(context.Background(), sampleFinding(), "x")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(gotLabels, ",")
	if !strings.Contains(joined, "env:prod") || !strings.Contains(joined, "team:ot") {
		t.Fatalf("extra labels missing: %v", gotLabels)
	}
}
