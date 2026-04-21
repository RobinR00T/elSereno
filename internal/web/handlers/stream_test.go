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
	var seen []string
	for {
		if time.Now().After(deadline) {
			t.Fatalf("drainUntil timeout; seen=%v", seen)
		}
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE line: %v; seen=%v", err, seen)
		}
		seen = append(seen, line)
		if matcher(line) {
			return
		}
	}
}

func TestStream_EmitsSSEFramedEvent(t *testing.T) {
	b := stream.New(8)
	srv := httptest.NewServer(handlers.Stream(b))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
	// Wait for the retry: hint so we know the handler has subscribed.
	drainUntil(t, r, time.Now().Add(1*time.Second), func(s string) bool {
		return strings.HasPrefix(s, "retry:")
	})

	// Publish after Subscribe has committed (i.e. after the retry
	// hint reaches us); otherwise the event may race the subscribe.
	id := b.Publish(stream.Event{
		Kind:    stream.EventFinding,
		Payload: []byte(`{"severity":"high"}`),
	})
	if id != 1 {
		t.Fatalf("Publish ID = %d", id)
	}

	// Read until we see the data: line — the framing is
	// "event:", "id:", "data:" in order, then a blank line.
	deadline := time.Now().Add(2 * time.Second)
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
