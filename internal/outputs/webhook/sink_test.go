package webhook_test

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

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/webhook"
)

func sampleFinding() core.Finding {
	ts, _ := time.Parse(time.RFC3339, "2026-04-19T10:00:00Z")
	return core.Finding{
		ID:          "f-001",
		RunID:       "r-9",
		Protocol:    "modbus",
		Severity:    core.SeverityHigh,
		Score:       75,
		Factors:     map[string]int{"protocol_risk": 85},
		FindingHash: []byte{0x01, 0x02, 0x03},
		CreatedAt:   ts,
	}
}

func TestSend_HappyPath_JSONShape(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := webhook.New(webhook.Config{URL: srv.URL})
	if err := s.Send(context.Background(), sampleFinding(), "10.0.0.1:502"); err != nil {
		t.Fatal(err)
	}
	var env webhook.Envelope
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatal(err)
	}
	if env.Schema != "webhook:v1" {
		t.Fatalf("schema: %q", env.Schema)
	}
	if env.FindingID != "f-001" || env.Protocol != "modbus" || env.Score != 75 {
		t.Fatalf("env: %+v", env)
	}
	if env.FindingHash != "010203" {
		t.Fatalf("hash: %q", env.FindingHash)
	}
	if env.Factors["protocol_risk"] != 85 {
		t.Fatalf("factor: %+v", env.Factors)
	}
}

func TestSend_HMACHeaderOnSecret(t *testing.T) {
	var gotBody []byte
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Elsereno-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	secret := []byte("k")
	s := webhook.New(webhook.Config{URL: srv.URL, Secret: secret})
	if err := s.Send(context.Background(), sampleFinding(), "x"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Fatalf("missing sig prefix: %q", gotSig)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if gotSig != want {
		t.Fatalf("sig mismatch")
	}
}

func TestSend_ExtraHeadersAttached(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Channel")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := webhook.New(webhook.Config{URL: srv.URL, ExtraHeaders: map[string]string{"X-Channel": "ops"}})
	_ = s.Send(context.Background(), sampleFinding(), "x")
	if got != "ops" {
		t.Fatalf("extra header missing: %q", got)
	}
}

func TestSend_EmptyURL(t *testing.T) {
	s := webhook.New(webhook.Config{})
	err := s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, webhook.ErrEmptyURL) {
		t.Fatalf("want ErrEmptyURL, got %v", err)
	}
}

func TestSend_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"err":"bad"}`))
	}))
	t.Cleanup(srv.Close)
	s := webhook.New(webhook.Config{URL: srv.URL})
	err := s.Send(context.Background(), sampleFinding(), "x")
	if !errors.Is(err, webhook.ErrNon2xx) {
		t.Fatalf("want ErrNon2xx, got %v", err)
	}
}
