// Package githubissues posts each Finding as a GitHub issue via the
// REST API (POST /repos/{owner}/{repo}/issues). Auth is Bearer with
// a fine-scoped personal access token held in the vault.
package githubissues

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"local/elsereno/internal/core"
)

// Contract is the schema identifier for GitHub-issues output.
const Contract = "github-issues:v1"

// Config holds the repo coordinates + auth.
type Config struct {
	// BaseURL is the GitHub API root; defaults to
	// https://api.github.com. Override for GHES.
	BaseURL string
	// Owner is the repo owner (user or org).
	Owner string
	// Repo is the repository name.
	Repo string
	// Token is the fine-scoped PAT (issues:write + metadata:read).
	Token []byte
	// LabelsExtra are applied in addition to the auto-generated
	// labels (severity, protocol, run id).
	LabelsExtra []string
	// Client is the HTTP client. Defaults to 10 s timeout.
	Client *http.Client
}

// Errors.
var (
	ErrEmptyRepo  = errors.New("githubissues: Owner / Repo empty")
	ErrEmptyToken = errors.New("githubissues: Token empty")
	ErrNon2xx     = errors.New("githubissues: API returned non-2xx")
)

// Sink wraps the HTTP client + config.
type Sink struct{ cfg Config }

// New returns a Sink with defaults filled in.
func New(cfg Config) *Sink {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.github.com"
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Sink{cfg: cfg}
}

// Send POSTs one issue per finding. Returns the issue number on
// success, 0 otherwise.
func (s *Sink) Send(ctx context.Context, f core.Finding, addr string) (int, error) {
	if s.cfg.Owner == "" || s.cfg.Repo == "" {
		return 0, ErrEmptyRepo
	}
	if len(s.cfg.Token) == 0 {
		return 0, ErrEmptyToken
	}
	payload := map[string]any{
		"title":  fmt.Sprintf("[elsereno] %s exposure on %s (score %d)", f.Protocol, addr, f.Score),
		"body":   s.buildBody(f, addr),
		"labels": s.buildLabels(f),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("githubissues: marshal: %w", err)
	}
	url := fmt.Sprintf("%s/repos/%s/%s/issues", s.cfg.BaseURL, s.cfg.Owner, s.cfg.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("githubissues: request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+string(s.cfg.Token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("githubissues: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("%w: %s: %s", ErrNon2xx, resp.Status, truncate(string(rb), 256))
	}
	var parsed struct {
		Number int `json:"number"`
	}
	if err := json.Unmarshal(rb, &parsed); err != nil {
		return 0, fmt.Errorf("githubissues: parse response: %w", err)
	}
	return parsed.Number, nil
}

func (s *Sink) buildBody(f core.Finding, addr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ElSereno finding `%s`\n\n", f.ID)
	fmt.Fprintf(&b, "- **Protocol**: %s\n", f.Protocol)
	fmt.Fprintf(&b, "- **Target**: `%s`\n", addr)
	fmt.Fprintf(&b, "- **Severity**: %s\n", f.Severity)
	fmt.Fprintf(&b, "- **Score**: %d / 100\n", f.Score)
	if f.RunID != "" {
		fmt.Fprintf(&b, "- **Run**: `%s`\n", f.RunID)
	}
	if len(f.Factors) > 0 {
		b.WriteString("\n**Factor breakdown**\n\n| Factor | Value |\n|---|---|\n")
		// Deterministic order.
		keys := make([]string, 0, len(f.Factors))
		for k := range f.Factors {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "| %s | %d |\n", k, f.Factors[k])
		}
	}
	return b.String()
}

func (s *Sink) buildLabels(f core.Finding) []string {
	labels := []string{
		"elsereno",
		"severity/" + string(f.Severity),
		"protocol/" + f.Protocol,
	}
	if f.RunID != "" {
		labels = append(labels, "run/"+string(f.RunID))
	}
	labels = append(labels, s.cfg.LabelsExtra...)
	return labels
}

// sortStrings wraps sort.Strings without pulling in the package
// import on every call site (we use it in one spot).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
