package canary_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/canary"
)

func TestSend_JSONAndSignature(t *testing.T) {
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = b
		gotSig = r.Header.Get("X-Elsereno-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	secret := []byte("shared-secret")
	s := canary.New(canary.Config{Enabled: true, URL: srv.URL, Secret: secret})
	err := s.Send(context.Background(), canary.Event{
		Kind:     "offensive_denied",
		Actor:    "operator",
		Target:   "10.0.0.1:502",
		Protocol: "modbus",
		Reason:   "--accept-writes not set",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(gotBody) == 0 {
		t.Fatal("body empty")
	}
	var back canary.Event
	if err := json.Unmarshal(gotBody, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Schema != "canary:v1" || back.Kind != "offensive_denied" {
		t.Fatalf("bad payload: %+v", back)
	}
	// Signature verification.
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("sig prefix missing: %q", gotSig)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("sig mismatch:\ngot  %s\nwant %s", gotSig, want)
	}
}

func TestSend_DisabledShortCircuit(t *testing.T) {
	s := canary.New(canary.Config{Enabled: false, URL: "http://never/"})
	err := s.Send(context.Background(), canary.Event{Kind: "x"})
	if !errors.Is(err, canary.ErrDisabled) {
		t.Fatalf("want ErrDisabled, got %v", err)
	}
}

func TestSend_EmptyURL(t *testing.T) {
	s := canary.New(canary.Config{Enabled: true, URL: ""})
	err := s.Send(context.Background(), canary.Event{Kind: "x"})
	if !errors.Is(err, canary.ErrNoURL) {
		t.Fatalf("want ErrNoURL, got %v", err)
	}
}

func TestSend_Non2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	s := canary.New(canary.Config{Enabled: true, URL: srv.URL})
	err := s.Send(context.Background(), canary.Event{Kind: "x"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got %v", err)
	}
}

func TestSend_DefaultsFilled(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := canary.New(canary.Config{Enabled: true, URL: srv.URL})
	err := s.Send(context.Background(), canary.Event{Kind: "scope_violation_target"})
	if err != nil {
		t.Fatal(err)
	}
	var ev canary.Event
	_ = json.Unmarshal(gotBody, &ev)
	if ev.Schema != "canary:v1" {
		t.Fatal("Schema default missing")
	}
	if ev.At.IsZero() || time.Since(ev.At) > 5*time.Second {
		t.Fatalf("At default missing or wrong: %v", ev.At)
	}
}

func TestInMemorySender(t *testing.T) {
	s := &canary.InMemorySender{}
	if err := s.Send(context.Background(), canary.Event{Kind: "k"}); err != nil {
		t.Fatal(err)
	}
	if len(s.Events) != 1 || s.Events[0].Kind != "k" {
		t.Fatalf("events: %+v", s.Events)
	}
	s.Fail = errors.New("synthetic")
	if err := s.Send(context.Background(), canary.Event{Kind: "z"}); err == nil {
		t.Fatal("expected failure")
	}
	if len(s.Events) != 1 {
		t.Fatalf("should not have stored on failure: %+v", s.Events)
	}
}
