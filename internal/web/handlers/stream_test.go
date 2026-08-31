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
	// Register cancel + body close as cleanups so they run even when an
	// assertion below fails early. Without this net, a failed Len check
	// would skip the manual cancel()/Close() and t.Cleanup(srv.Close)
	// would then block until the 10-minute test-framework timeout,
	// waiting for the leaked SSE handler goroutine to return (the hang
	// that flaked this test on loaded CI runners).
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })

	// The handler emits the retry: hint BEFORE it calls Subscribe(), so
	// observing retry: does not prove the subscription exists yet. Poll
	// the broadcaster's subscriber count directly — that is the state
	// under test — instead of racing on the hint's arrival (the old 1s
	// drainUntil race is what made this test flaky under runner load).
	subDeadline := time.Now().Add(30 * time.Second)
	for b.Len() == 0 {
		if time.Now().After(subDeadline) {
			t.Fatal("handler did not register its subscription in time")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if n := b.Len(); n != 1 {
		t.Fatalf("after connect Len = %d, want 1", n)
	}

	// Cancelling the request must make the handler observe ctx.Done and
	// release its broadcaster slot.
	cancel()
	_ = resp.Body.Close()

	deadline := time.Now().Add(30 * time.Second)
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
