//go:build !mini

package feeds

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
	"local/elsereno/internal/tui"
)

// Watch is the read-only SSE consumer that subscribes to a remote
// dashboard's `/api/v1/stream` endpoint. Pairs with the
// Broadcaster running inside `elsereno serve` so an operator can
// drive a TUI on a workstation while the actual scanning runs on
// a jump host:
//
//	elsereno tui --watch https://jumphost:8443/api/v1/stream \
//	            --bearer "$TOKEN"
//
// Decodes the SSE framing (event:, id:, data:, blank-line
// separator), routes by event kind:
//
//   - finding     → tui.FindingMsg
//   - audit       → tui.AuditMsg with the operator-visible payload
//   - run_start   → tui.AuditMsg announcing the run
//   - run_end     → tui.AuditMsg with the final counts
//
// Reconnects automatically on transient I/O errors (default
// retry 3s, matching the server's `retry:` hint). Auth failures
// (401/403) terminate the feed — the operator needs a fresh
// token, not another retry.
type Watch struct {
	// URL is the SSE endpoint, e.g. "https://host/api/v1/stream".
	// Required.
	URL string
	// Bearer is the Authorization token. Required for any
	// non-loopback URL — `serve` rejects unauthenticated stream
	// connections (per ADR-009).
	Bearer string
	// Client lets tests inject a mock transport. nil → DefaultClient.
	Client *http.Client
	// RetryInterval is the wallclock pause between reconnect
	// attempts. 0 → 3s (matches the server's SSE retry: hint).
	RetryInterval time.Duration
	// MaxRetries bounds reconnect attempts. 0 → unbounded
	// (interactive sessions; the operator quits with q). >0 is
	// useful for tests + scripted runs.
	MaxRetries int
}

// Name implements tui.Feed.
func (w Watch) Name() string { return "watch " + w.URL }

// Run implements tui.Feed. Loops connect → consume → on error
// retry with backoff until ctx cancels or auth permanently fails.
func (w Watch) Run(ctx context.Context, emit func(tea.Msg)) error {
	if w.URL == "" {
		return errors.New("watch: empty URL")
	}
	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	retry := w.RetryInterval
	if retry == 0 {
		retry = 3 * time.Second
	}

	attempts := 0
	for {
		err := w.consume(ctx, client, emit)
		if err == nil {
			return nil // server closed the stream cleanly
		}
		// Auth failures are terminal — we'd loop forever otherwise.
		var ae authError
		if errors.As(err, &ae) {
			return err
		}
		// Cancellation propagates without a reconnect.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		attempts++
		if w.MaxRetries > 0 && attempts >= w.MaxRetries {
			return fmt.Errorf("watch: gave up after %d retries: %w", attempts, err)
		}
		// Surface the disconnect so the operator sees it.
		emit(tui.AuditMsg{
			Line: fmt.Sprintf("watch: disconnected (%v); retry in %v", err, retry),
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retry):
		}
	}
}

// consume opens one HTTP connection and decodes events until the
// server closes or an error happens. Returning nil means clean
// EOF (server shut down gracefully); any other return is fed
// back to Run for the retry decision.
func (w Watch) consume(ctx context.Context, client *http.Client, emit func(tea.Msg)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.URL, nil)
	if err != nil {
		return fmt.Errorf("watch: build request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if w.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+w.Bearer)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("watch: dial: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return authError{Status: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch: unexpected status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		return fmt.Errorf("watch: unexpected content-type %q (want text/event-stream)", ct)
	}

	return decodeSSE(ctx, resp.Body, emit)
}

// decodeSSE parses the SSE framing + dispatches each event to
// the matching tui.Msg.
func decodeSSE(ctx context.Context, body io.Reader, emit func(tea.Msg)) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var ev sseEvent
	for scanner.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Text()
		if line == "" {
			// Blank line = event boundary. Dispatch + reset.
			if ev.kind != "" || len(ev.data) > 0 {
				dispatchSSE(ev, emit)
			}
			ev = sseEvent{}
			continue
		}
		if strings.HasPrefix(line, ":") {
			// Comment ("`: keepalive`"); ignore.
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// SSE allows a single space after the colon — strip it.
		value = strings.TrimPrefix(value, " ")
		switch key {
		case "event":
			ev.kind = value
		case "data":
			// Multi-line data fields concat with newline per the
			// SSE spec. Most ElSereno events are single-line JSON
			// so this rarely matters — but the spec is the spec.
			if len(ev.data) > 0 {
				ev.data = append(ev.data, '\n')
			}
			ev.data = append(ev.data, value...)
		case "id", "retry":
			// We don't reconnect with Last-Event-ID (the
			// broadcaster doesn't support replay); ignore.
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("watch: read: %w", err)
	}
	return nil
}

// sseEvent is the parsed accumulator for a single event. Reset
// to zero on every blank line.
type sseEvent struct {
	kind string
	data []byte
}

// dispatchSSE routes one parsed event to the correct tui.Msg.
// Unknown event kinds are surfaced as AuditMsg so a future
// schema bump doesn't silently drop new payloads.
func dispatchSSE(ev sseEvent, emit func(tea.Msg)) {
	switch ev.kind {
	case "finding":
		var p findingPayload
		if err := json.Unmarshal(ev.data, &p); err != nil {
			emit(tui.AuditMsg{Line: fmt.Sprintf("watch: drop malformed finding: %v", err)})
			return
		}
		emit(tui.FindingMsg{Finding: core.Finding{
			ID:        core.UUID(p.ID),
			RunID:     core.UUID(p.RunID),
			TargetID:  core.UUID(p.TargetID),
			Protocol:  p.Protocol,
			Severity:  core.Severity(p.Severity),
			Score:     p.Score,
			Factors:   p.Factors,
			CreatedAt: p.CreatedAt,
		}})
	case "audit":
		var p auditPayload
		if err := json.Unmarshal(ev.data, &p); err != nil {
			emit(tui.AuditMsg{Line: fmt.Sprintf("watch: drop malformed audit: %v", err)})
			return
		}
		emit(tui.AuditMsg{
			Line: fmt.Sprintf("audit %s @ %s by %s",
				p.EventType, p.OccurredAt.UTC().Format(time.RFC3339), p.Actor),
		})
	case "run_start":
		var p runStartPayload
		if err := json.Unmarshal(ev.data, &p); err != nil {
			emit(tui.AuditMsg{Line: fmt.Sprintf("watch: drop malformed run_start: %v", err)})
			return
		}
		emit(tui.AuditMsg{
			Line: fmt.Sprintf("run %s started by %s @ %s",
				p.RunID, p.Operator, p.StartedAt.UTC().Format(time.RFC3339)),
		})
	case "run_end":
		var p runEndPayload
		if err := json.Unmarshal(ev.data, &p); err != nil {
			emit(tui.AuditMsg{Line: fmt.Sprintf("watch: drop malformed run_end: %v", err)})
			return
		}
		emit(tui.AuditMsg{
			Line: fmt.Sprintf("run %s ended (%s); counts %v",
				p.RunID, p.Status, p.Counts),
		})
	default:
		emit(tui.AuditMsg{
			Line: fmt.Sprintf("watch: unknown event %q (%d bytes payload)",
				ev.kind, len(ev.data)),
		})
	}
}

// authError flags an HTTP 401/403 so the retry loop short-
// circuits — looping forever on a bad token is just noise.
type authError struct {
	Status int
}

func (a authError) Error() string {
	return fmt.Sprintf("watch: auth failed (HTTP %d); refresh token", a.Status)
}

// findingPayload mirrors web/stream.findingWirePayload. Kept in
// this package so the TUI doesn't import the web tree (ADR-005:
// CLI must compile without the dashboard).
type findingPayload struct {
	ID        string         `json:"id"`
	RunID     string         `json:"run_id"`
	TargetID  string         `json:"target_id"`
	Protocol  string         `json:"protocol"`
	Severity  string         `json:"severity"`
	Score     int            `json:"score"`
	CreatedAt time.Time      `json:"created_at"`
	Factors   map[string]int `json:"factors,omitempty"`
}

type auditPayload struct {
	ID         int64           `json:"id"`
	EventType  string          `json:"event_type"`
	Actor      string          `json:"actor"`
	OccurredAt time.Time       `json:"occurred_at"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

type runStartPayload struct {
	RunID     string    `json:"run_id"`
	Operator  string    `json:"operator"`
	StartedAt time.Time `json:"started_at"`
}

type runEndPayload struct {
	RunID      string         `json:"run_id"`
	Status     string         `json:"status"`
	FinishedAt time.Time      `json:"finished_at"`
	Counts     map[string]int `json:"counts,omitempty"`
}
