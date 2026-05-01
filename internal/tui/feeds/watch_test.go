//go:build !mini

package feeds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"local/elsereno/internal/tui"
)

// flusherWriter wraps a ResponseWriter so the test handler can
// stream events without buffering. httptest.NewServer's default
// writer supports Flush, so we type-assert + call it directly.
func flush(w http.ResponseWriter) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// writeSSE writes one event in the SSE wire format.
func writeSSE(w http.ResponseWriter, kind, data string) {
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, data)
	flush(w)
}

// findingPayloadJSON is the minimum-valid finding wire payload.
func findingPayloadJSON(score int) string {
	return fmt.Sprintf(`{"id":"f1","run_id":"r1","target_id":"t1","protocol":"modbus","severity":"high","score":%d,"created_at":"2026-04-29T12:00:00Z","factors":{"banner":50}}`, score)
}

// TestWatchHappyPath dials the test server, consumes 2 finding
// events + a run_end, then sees the server close the stream.
// Asserts FindingMsgs land and the run_end becomes an AuditMsg.
func TestWatchHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSE(w, "finding", findingPayloadJSON(85))
		writeSSE(w, "finding", findingPayloadJSON(95))
		writeSSE(w, "run_end", `{"run_id":"r1","status":"completed","finished_at":"2026-04-29T12:00:05Z","counts":{"high":1,"critical":1}}`)
	}))
	defer srv.Close()

	d := &drain{}
	feed := Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 1}
	if err := feed.Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := len(d.msgs); got != 3 {
		t.Fatalf("emitted %d, want 3", got)
	}
	if _, ok := d.msgs[0].(tui.FindingMsg); !ok {
		t.Errorf("[0] = %T, want FindingMsg", d.msgs[0])
	}
	if _, ok := d.msgs[1].(tui.FindingMsg); !ok {
		t.Errorf("[1] = %T, want FindingMsg", d.msgs[1])
	}
	am, ok := d.msgs[2].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[2] = %T, want AuditMsg", d.msgs[2])
	}
	if !strings.Contains(am.Line, "run r1 ended") {
		t.Errorf("[2] line = %q, want 'run r1 ended'", am.Line)
	}
}

// TestWatchRoutesEachEventKind drives one of every kind and
// confirms each maps to the right tui.Msg shape with sane content.
func TestWatchRoutesEachEventKind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSE(w, "finding", findingPayloadJSON(60))
		writeSSE(w, "audit", `{"id":7,"event_type":"vault_unlock","actor":"alice","occurred_at":"2026-04-29T11:00:00Z"}`)
		writeSSE(w, "run_start", `{"run_id":"r1","operator":"alice","started_at":"2026-04-29T12:00:00Z"}`)
		writeSSE(w, "run_end", `{"run_id":"r1","status":"completed","finished_at":"2026-04-29T12:01:00Z","counts":{"medium":1}}`)
	}))
	defer srv.Close()

	d := &drain{}
	if err := (Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 1}).Run(context.Background(), d.emit()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := len(d.msgs); got != 4 {
		t.Fatalf("emitted %d, want 4", got)
	}
	if _, ok := d.msgs[0].(tui.FindingMsg); !ok {
		t.Errorf("[0] = %T, want FindingMsg", d.msgs[0])
	}
	for i := 1; i < 4; i++ {
		if _, ok := d.msgs[i].(tui.AuditMsg); !ok {
			t.Errorf("[%d] = %T, want AuditMsg", i, d.msgs[i])
		}
	}
	audit1, ok := d.msgs[1].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[1] = %T, want AuditMsg", d.msgs[1])
	}
	if !strings.Contains(audit1.Line, "vault_unlock") || !strings.Contains(audit1.Line, "alice") {
		t.Errorf("audit line missing fields: %q", audit1.Line)
	}
	audit2, ok := d.msgs[2].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[2] = %T, want AuditMsg", d.msgs[2])
	}
	if !strings.Contains(audit2.Line, "started by alice") {
		t.Errorf("run_start line: %q", audit2.Line)
	}
}

// TestWatchUnknownEventSurfaced — a future schema bump that
// emits a new event kind shouldn't be silently dropped; the
// operator sees an explicit "unknown event" line.
func TestWatchUnknownEventSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSE(w, "future_kind", `{"x":1}`)
	}))
	defer srv.Close()

	d := &drain{}
	_ = (Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 1}).Run(context.Background(), d.emit())
	if len(d.msgs) != 1 {
		t.Fatalf("emitted %d, want 1", len(d.msgs))
	}
	am, ok := d.msgs[0].(tui.AuditMsg)
	if !ok {
		t.Fatalf("got %T", d.msgs[0])
	}
	if !strings.Contains(am.Line, "unknown event \"future_kind\"") {
		t.Errorf("line = %q, want 'unknown event'", am.Line)
	}
}

// TestWatchAuthorizationHeader — the bearer token must travel
// on the request as `Authorization: Bearer <token>`. Server-side
// inspection confirms the wire format.
func TestWatchAuthorizationHeader(t *testing.T) {
	var seenAuth atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		seenAuth.Store(&got)
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSE(w, "finding", findingPayloadJSON(50))
	}))
	defer srv.Close()

	_ = (Watch{URL: srv.URL, Bearer: "s3cret", Client: srv.Client(), MaxRetries: 1}).Run(context.Background(), (&drain{}).emit())
	got := seenAuth.Load()
	if got == nil || *got != "Bearer s3cret" {
		t.Errorf("Authorization = %v, want 'Bearer s3cret'", got)
	}
}

// TestWatchAuthFailureTerminates — 401 short-circuits the retry
// loop. Looping on a bad token would just spam the server.
func TestWatchAuthFailureTerminates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	err := (Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 5}).Run(context.Background(), (&drain{}).emit())
	if err == nil {
		t.Fatal("expected error on 401")
	}
	var ae authError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v, want authError", err)
	}
	if ae.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", ae.Status)
	}
}

// TestWatchUnexpectedStatusRetries — a 500 from the server is
// transient; the retry loop should re-dial on the next tick.
// We use MaxRetries=1 to bound the test + check that we see one
// disconnect AuditMsg before the loop gives up.
func TestWatchUnexpectedStatusRetries(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	d := &drain{}
	err := (Watch{
		URL:           srv.URL,
		Client:        srv.Client(),
		RetryInterval: 10 * time.Millisecond,
		MaxRetries:    2,
	}).Run(context.Background(), d.emit())
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	if !strings.Contains(err.Error(), "gave up after 2 retries") {
		t.Errorf("err = %v, want retry exhaustion", err)
	}
	if hits.Load() < 2 {
		t.Errorf("hits = %d, want ≥2 (retry loop should re-dial)", hits.Load())
	}
	// At least one AuditMsg should have been emitted between
	// retries to keep the operator informed.
	gotAudit := false
	for _, m := range d.msgs {
		if am, ok := m.(tui.AuditMsg); ok && strings.Contains(am.Line, "disconnected") {
			gotAudit = true
		}
	}
	if !gotAudit {
		t.Errorf("no 'disconnected' AuditMsg emitted")
	}
}

// TestWatchRejectsNonStreamContentType — a server returning
// JSON or HTML instead of text/event-stream is misconfigured;
// surface as an error rather than mis-decoding.
func TestWatchRejectsNonStreamContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hello":"world"}`))
	}))
	defer srv.Close()

	err := (Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 1}).Run(context.Background(), (&drain{}).emit())
	if err == nil || !strings.Contains(err.Error(), "unexpected content-type") {
		t.Errorf("err = %v, want content-type error", err)
	}
}

// TestWatchEmptyURL — Run rejects up front.
func TestWatchEmptyURL(t *testing.T) {
	err := (Watch{}).Run(context.Background(), (&drain{}).emit())
	if err == nil || !strings.Contains(err.Error(), "empty URL") {
		t.Errorf("err = %v, want 'empty URL'", err)
	}
}

// TestWatchIgnoresKeepaliveComments — the server emits
// `: keepalive` comments every ~15s; the parser must skip them
// without producing AuditMsgs (would clutter the audit pane).
func TestWatchIgnoresKeepaliveComments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, ": keepalive\n\n")
		flush(w)
		writeSSE(w, "finding", findingPayloadJSON(50))
		_, _ = io.WriteString(w, ": keepalive\n\n")
		flush(w)
	}))
	defer srv.Close()

	d := &drain{}
	_ = (Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 1}).Run(context.Background(), d.emit())
	if got := len(d.msgs); got != 1 {
		t.Errorf("emitted %d, want 1 (keepalive comments must not surface)", got)
	}
}

// TestWatchContextCancel — pulling the context terminates Run
// without a retry attempt.
func TestWatchContextCancel(t *testing.T) {
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flush(w)
		<-hold // never returns
	}))
	defer srv.Close()
	defer close(hold)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (Watch{URL: srv.URL, Client: srv.Client()}).Run(ctx, (&drain{}).emit()) }()

	// Give the request time to dial.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}
}

// TestWatchMalformedJSONLogged — a finding with bad JSON
// becomes an AuditMsg + the stream continues. Mirrors replay /
// stdin behaviour: never abort on one bad record.
func TestWatchMalformedJSONLogged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		writeSSE(w, "finding", `{this is not valid`)
		writeSSE(w, "finding", findingPayloadJSON(75))
	}))
	defer srv.Close()

	d := &drain{}
	_ = (Watch{URL: srv.URL, Client: srv.Client(), MaxRetries: 1}).Run(context.Background(), d.emit())
	if got := len(d.msgs); got != 2 {
		t.Fatalf("emitted %d, want 2 (1 audit + 1 finding)", got)
	}
	if _, ok := d.msgs[0].(tui.AuditMsg); !ok {
		t.Errorf("[0] = %T, want AuditMsg", d.msgs[0])
	}
	if _, ok := d.msgs[1].(tui.FindingMsg); !ok {
		t.Errorf("[1] = %T, want FindingMsg", d.msgs[1])
	}
}

// TestWatchName — identifier includes the URL for error reports.
func TestWatchName(t *testing.T) {
	if got := (Watch{URL: "https://x"}).Name(); got != "watch https://x" {
		t.Errorf("Name = %q", got)
	}
}

// TestDecodeSSEMultiLineData — per the SSE spec, multiple
// `data:` lines for one event concat with newlines into a
// single payload. We split a valid JSON payload across two
// data: lines + confirm the dispatcher reassembles it into
// one FindingMsg with the right score.
func TestDecodeSSEMultiLineData(t *testing.T) {
	body := "event: finding\n" +
		`data: {"id":"f1","run_id":"r1","target_id":"t1","protocol":"modbus","severity":"high",` + "\n" +
		`data: "score":85,"created_at":"2026-04-29T12:00:00Z"}` + "\n\n"
	d := &drain{}
	if err := decodeSSE(context.Background(), strings.NewReader(body), d.emit()); err != nil {
		t.Fatalf("decodeSSE: %v", err)
	}
	if len(d.msgs) != 1 {
		t.Fatalf("emitted %d, want 1", len(d.msgs))
	}
	fm, ok := d.msgs[0].(tui.FindingMsg)
	if !ok {
		t.Fatalf("got %T, want FindingMsg", d.msgs[0])
	}
	if fm.Finding.Score != 85 {
		t.Errorf("score = %d, want 85 (multi-line concat may have dropped a chunk)", fm.Finding.Score)
	}
}
