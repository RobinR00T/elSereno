// Package jira posts each Finding as an issue into a JIRA project
// via the Cloud REST v3 API. Auth is HTTP Basic with
// email:api_token (per the JIRA Cloud policy) — callers hold the
// token in the vault and pass the bytes at Send time.
package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"local/elsereno/internal/core"
)

// Contract is the schema identifier for JIRA-issue output.
const Contract = "jira:v1"

// Config holds the JIRA project identification + auth.
type Config struct {
	// BaseURL is the JIRA Cloud base URL ending at the tenant, e.g.
	// "https://acme.atlassian.net". Trailing slash is tolerated.
	BaseURL string
	// ProjectKey is the issue's target project, e.g. "OT".
	ProjectKey string
	// Email is the user the API token was minted for.
	Email string
	// APIToken is the secret. Hold in the vault; never log.
	APIToken []byte
	// IssueType defaults to "Task" when empty.
	IssueType string
	// LabelsExtra are applied to every issue on top of the auto-
	// generated labels (severity, protocol, run id).
	LabelsExtra []string
	// Client is the HTTP client. Defaults to a client with a 10 s
	// timeout.
	Client *http.Client
}

// Errors returned by Send.
var (
	ErrEmptyBaseURL = errors.New("jira: BaseURL empty")
	ErrEmptyProject = errors.New("jira: ProjectKey empty")
	ErrEmptyAuth    = errors.New("jira: Email / APIToken empty")
	ErrNon2xx       = errors.New("jira: API returned non-2xx")
)

// Sink wraps the HTTP client + config. One Sink per project per run.
type Sink struct{ cfg Config }

// New returns a Sink with defaults filled in.
func New(cfg Config) *Sink {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.IssueType == "" {
		cfg.IssueType = "Task"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Sink{cfg: cfg}
}

// Send POSTs one JIRA issue per Finding. Returns the newly-created
// issue key on success (e.g. "OT-1234"), empty string otherwise.
func (s *Sink) Send(ctx context.Context, f core.Finding, addr string) (string, error) {
	if s.cfg.BaseURL == "" {
		return "", ErrEmptyBaseURL
	}
	if s.cfg.ProjectKey == "" {
		return "", ErrEmptyProject
	}
	if s.cfg.Email == "" || len(s.cfg.APIToken) == 0 {
		return "", ErrEmptyAuth
	}
	body, err := json.Marshal(s.buildPayload(f, addr))
	if err != nil {
		return "", fmt.Errorf("jira: marshal: %w", err)
	}
	url := s.cfg.BaseURL + "/rest/api/3/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("jira: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	auth := base64.StdEncoding.EncodeToString([]byte(s.cfg.Email + ":" + string(s.cfg.APIToken)))
	req.Header.Set("Authorization", "Basic "+auth)

	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("jira: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%w: %s: %s", ErrNon2xx, resp.Status, truncate(string(rb), 256))
	}
	var parsed struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return "", fmt.Errorf("jira: parse response: %w", err)
	}
	return parsed.Key, nil
}

// buildPayload constructs the JIRA v3 issue JSON. The description
// uses the Atlassian Document Format (ADF) with a single paragraph —
// a minimum-viable format that avoids pulling in a large ADF builder
// while still rendering correctly in the JIRA UI.
func (s *Sink) buildPayload(f core.Finding, addr string) map[string]any {
	summary := fmt.Sprintf("%s exposure on %s (score %d, %s)",
		f.Protocol, addr, f.Score, f.Severity)
	desc := fmt.Sprintf(
		"ElSereno finding %s\n\nProtocol: %s\nTarget: %s\nSeverity: %s\nScore: %d\nRun: %s",
		f.ID, f.Protocol, addr, f.Severity, f.Score, f.RunID,
	)
	labels := []string{
		"elsereno",
		"severity:" + string(f.Severity),
		"protocol:" + f.Protocol,
	}
	if f.RunID != "" {
		labels = append(labels, "run:"+string(f.RunID))
	}
	labels = append(labels, s.cfg.LabelsExtra...)
	return map[string]any{
		"fields": map[string]any{
			"project":   map[string]string{"key": s.cfg.ProjectKey},
			"summary":   summary,
			"issuetype": map[string]string{"name": s.cfg.IssueType},
			"labels":    labels,
			"priority":  map[string]string{"name": severityToPriority(f.Severity)},
			"description": map[string]any{
				"type":    "doc",
				"version": 1,
				"content": []map[string]any{
					{
						"type": "paragraph",
						"content": []map[string]any{
							{"type": "text", "text": desc},
						},
					},
				},
			},
		},
	}
}

// severityToPriority maps ElSereno severity to JIRA's default
// priority-scheme name. Tenants with a custom scheme can override via
// LabelsExtra plus a workflow automation.
func severityToPriority(s core.Severity) string {
	switch strings.ToLower(string(s)) {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Lowest"
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
