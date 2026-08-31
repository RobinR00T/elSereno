package handlers_test

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/web/handlers"
	"local/elsereno/internal/web/stream"
)

// drainUntil reads lines from r until one matches matcher or the
// deadline hits. On timeout / read error it reports every line
// seen so far via t.Fatalf.
func drainUntil(t *testing.T, r *bufio.Reader, deadline time.Time, matcher func(string) bool) {
	t.Helper()
	type readResult struct {
		line string
		err  error
	}
	var seen []string
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("drainUntil timeout; seen=%v", seen)
		}
		// Read one line in a goroutine so a ReadString that blocks
		// (the server never sends the awaited line, e.g. under runner
		// load) is bounded by the deadline instead of hanging until the
		// 10-minute test-framework timeout. One reader at a time: the
		// select waits for the line before the next iteration, so there
		// is no concurrent access to r on the success path.
		ch := make(chan readResult, 1)
		go func() { line, err := r.ReadString('\n'); ch <- readResult{line, err} }()
		select {
		case rr := <-ch:
			if rr.err != nil {
				t.Fatalf("read SSE line: %v; seen=%v", rr.err, seen)
			}
			seen = append(seen, rr.line)
			if matcher(rr.line) {
				return
			}
		case <-time.After(remaining):
			t.Fatalf("drainUntil timeout (read blocked); seen=%v", seen)
		}
	}
}

func TestStream_EmitsSSEFramedEvent(t *testing.T) {
	b := stream.New(8)
	srv := httptest.NewServer(handlers.Stream(b))
	t.Cleanup(srv.Close)

	// This test observes SSE frame ORDERING, not speed. Under -race on a
	// loaded CI runner the httptest server + goroutine scheduling can lag
	// many seconds, so the budget is deliberately generous; normally it
	// finishes in milliseconds. The determinism below (not the timeout)
	// is what fixes the flakiness.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type: %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-cache") {
		t.Fatalf("Cache-Control: %q", got)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("X-Accel-Buffering: %q", got)
	}

	r := bufio.NewReader(resp.Body)
	// Publish only AFTER the handler has registered its subscription,
	// confirmed deterministically via the broadcaster's subscriber count
	// rather than by racing on the wall-clock arrival of the retry: hint.
	// This removes the publish-before-subscribe race that made the test
	// flaky (a lost event that then times out the read).
	subDeadline := time.Now().Add(30 * time.Second)
	for b.Len() == 0 {
		if time.Now().After(subDeadline) {
			t.Fatal("handler did not register its subscription in time")
		}
		time.Sleep(2 * time.Millisecond)
	}

	id := b.Publish(stream.Event{
		Kind:    stream.EventFinding,
		Payload: []byte(`{"severity":"high"}`),
	})
	if id != 1 {
		t.Fatalf("Publish ID = %d", id)
	}

	// Read until we see the data: line — the framing is
	// "event:", "id:", "data:" in order (the retry: hint precedes them
	// and is ignored). Deadline sits inside the request context.
	deadline := time.Now().Add(45 * time.Second)
	var sawEvent, sawID, sawData bool
	for !sawData {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read sse: %v", err)
		}
		switch {
		case strings.HasPrefix(line, "event: finding"):
			sawEvent = true
		case strings.HasPrefix(line, "id: 1"):
			sawID = true
		case strings.HasPrefix(line, `data: {"severity":"high"}`):
			sawData = true
		}
		if time.Now().After(deadline) {
			t.Fatalf("sse framing timeout — event=%v id=%v data=%v", sawEvent, sawID, sawData)
		}
	}
	if !sawEvent || !sawID {
		t.Fatalf("missing SSE fields — event=%v id=%v data=%v", sawEvent, sawID, sawData)
	}
}

func TestStream_ClientCancelReleasesSubscription(t *testing.T) {
	b := stream.New(8)
	srv := httptest.NewServer(handlers.Stream(b))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	// Read the retry hint so we know the handler subscribed.
	r := bufio.NewReader(resp.Body)
	drainUntil(t, r, time.Now().Add(1*time.Second), func(s string) bool {
		return strings.HasPrefix(s, "retry:")
	})
	if n := b.Len(); n != 1 {
		t.Fatalf("after connect Len = %d, want 1", n)
	}
	cancel()
	_ = resp.Body.Close()

	// Wait up to 1s for the handler to observe ctx.Done and call
	// cancel — background tasks are async, so we poll.
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if b.Len() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("subscription not released; Len = %d", b.Len())
}

func TestAPIV1_NilBroadcasterReturns503(t *testing.T) {
	h := handlers.APIV1(handlers.APIV1Deps{})
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/stream", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
