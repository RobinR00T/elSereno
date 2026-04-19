// Package webhook posts each Finding as a JSON envelope to an
// operator-declared URL. Optional HMAC-SHA256 signing in the
// X-Elsereno-Signature header lets receivers verify origin.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"local/elsereno/internal/core"
)

// Contract is the schema identifier for the generic webhook envelope.
const Contract = "webhook:v1"

// Envelope is the JSON body sent on each POST. Flat shape so
// downstream consumers can filter without schema introspection.
type Envelope struct {
	Schema      string         `json:"schema"`
	FindingID   string         `json:"finding_id"`
	RunID       string         `json:"run_id,omitempty"`
	Protocol    string         `json:"protocol"`
	Severity    string         `json:"severity"`
	Score       int            `json:"score"`
	Target      string         `json:"target"`
	Factors     map[string]int `json:"factors,omitempty"`
	FindingHash string         `json:"finding_hash,omitempty"`
	CreatedAt   string         `json:"created_at"`
}

// Config holds the URL + optional signing secret.
type Config struct {
	// URL is the webhook endpoint.
	URL string
	// Secret, when non-empty, HMAC-SHA256-signs each body into the
	// X-Elsereno-Signature header.
	Secret []byte
	// ExtraHeaders are attached to every request — useful for custom
	// auth schemes (Slack, Teams, etc.). Callers must not put secrets
	// here if the HTTP client logs full request traces; use Secret.
	ExtraHeaders map[string]string
	// Client is the HTTP client. Defaults to 10 s timeout.
	Client *http.Client
}

// Errors.
var (
	ErrEmptyURL = errors.New("webhook: URL empty")
	ErrNon2xx   = errors.New("webhook: endpoint returned non-2xx")
)

// Sink wraps HTTP client + config.
type Sink struct{ cfg Config }

// New returns a Sink with defaults.
func New(cfg Config) *Sink {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Sink{cfg: cfg}
}

// Send POSTs one Envelope per Finding.
func (s *Sink) Send(ctx context.Context, f core.Finding, addr string) error {
	if s.cfg.URL == "" {
		return ErrEmptyURL
	}
	env := Envelope{
		Schema:      Contract,
		FindingID:   string(f.ID),
		RunID:       string(f.RunID),
		Protocol:    f.Protocol,
		Severity:    string(f.Severity),
		Score:       f.Score,
		Target:      addr,
		Factors:     f.Factors,
		FindingHash: hex.EncodeToString(f.FindingHash),
		CreatedAt:   f.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(s.cfg.Secret) > 0 {
		mac := hmac.New(sha256.New, s.cfg.Secret)
		_, _ = mac.Write(body)
		req.Header.Set("X-Elsereno-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	for k, v := range s.cfg.ExtraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: %s: %s", ErrNon2xx, resp.Status, truncate(string(rb), 256))
	}
	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// Ensure the strings import is always referenced so future refactors
// can add header parsing without re-adding the import.
var _ = strings.TrimSpace
