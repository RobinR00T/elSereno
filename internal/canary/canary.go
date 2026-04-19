package canary

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Event is a single canary payload. It is sent as JSON to the
// configured webhook with an HMAC-SHA256 signature over the body.
type Event struct {
	// Schema is always "canary:v1"; pins the envelope so
	// downstream parsers fail fast on upgrade.
	Schema string `json:"schema"`
	// Kind labels the canary category — one of
	// "scope_violation_target", "scope_violation_protocol",
	// "scope_violation_dial", "offensive_denied".
	Kind string `json:"kind"`
	// Actor is the operator name emitting the canary.
	Actor string `json:"actor,omitempty"`
	// Target is the host:port or dial number that triggered the
	// canary. Free text; the webhook receiver is expected to
	// store it for audit.
	Target string `json:"target,omitempty"`
	// Protocol is the plugin / tool that produced the violation.
	Protocol string `json:"protocol,omitempty"`
	// Reason is the typed error from the validator that fired.
	Reason string `json:"reason"`
	// At is the event timestamp (RFC3339 with microseconds).
	At time.Time `json:"at"`
}

// Sender is the small surface the caller uses. A real HTTP-posting
// sender is returned by New; tests substitute InMemorySender.
type Sender interface {
	Send(ctx context.Context, ev Event) error
}

// Config holds the webhook target and the HMAC signing secret.
// When Secret is empty, the signature header is omitted; receivers
// without shared-secret support can still parse the JSON.
type Config struct {
	Enabled bool
	URL     string
	// Secret is the HMAC key. Derived from the vault in real
	// deployment (HKDF info="elsereno/canary/webhook/v1").
	Secret []byte
	// Client is the HTTP client. New() defaults to an http.Client
	// with a 5s timeout.
	Client *http.Client
}

// Errors.
var (
	ErrDisabled = errors.New("canary: webhook disabled")
	ErrNoURL    = errors.New("canary: URL empty")
)

// New returns a real HTTP sender that POSTs Events as JSON to
// cfg.URL. When cfg.Enabled is false, Send returns ErrDisabled
// (the caller typically ignores this).
func New(cfg Config) Sender {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}
	return &httpSender{cfg: cfg}
}

type httpSender struct{ cfg Config }

// Send implements Sender. It returns nil on 2xx responses; any
// network error or non-2xx status wraps into a typed error so the
// caller can log without blocking.
func (s *httpSender) Send(ctx context.Context, ev Event) error {
	if !s.cfg.Enabled {
		return ErrDisabled
	}
	if s.cfg.URL == "" {
		return ErrNoURL
	}
	if ev.Schema == "" {
		ev.Schema = "canary:v1"
	}
	if ev.At.IsZero() {
		ev.At = time.Now().UTC().Truncate(time.Microsecond)
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("canary: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("canary: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(s.cfg.Secret) > 0 {
		mac := hmac.New(sha256.New, s.cfg.Secret)
		_, _ = mac.Write(body)
		req.Header.Set("X-Elsereno-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("canary: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("canary: webhook returned %s", resp.Status)
	}
	return nil
}

// InMemorySender captures events into a slice for tests. Safe for
// single-goroutine use — tests that care about concurrent sends
// should add their own mutex.
type InMemorySender struct {
	Events []Event
	// Fail, when set, causes Send to return this error without
	// storing the event.
	Fail error
}

// Send implements Sender.
func (s *InMemorySender) Send(_ context.Context, ev Event) error {
	if s.Fail != nil {
		return s.Fail
	}
	s.Events = append(s.Events, ev)
	return nil
}
