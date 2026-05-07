package stream_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/stream"
)

// drainOne reads at most one event from sub with a 100ms
// deadline. Returns ok=false if no event arrived.
func drainOne(t *testing.T, sub <-chan stream.Event) (stream.Event, bool) {
	t.Helper()
	select {
	case ev := <-sub:
		return ev, true
	case <-time.After(100 * time.Millisecond):
		return stream.Event{}, false
	}
}

// TestPublishScanState_EmitsCorrectKind: a queued Job becomes a
// scan_state_change event with the right shape.
func TestPublishScanState_EmitsCorrectKind(t *testing.T) {
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	job := scanorch.Job{
		ID:        "abc12345",
		State:     scanorch.StateQueued,
		CreatedAt: time.Now().UTC(),
		Input:     "stdin",
		Plugins:   []string{"modbus"},
		Operator:  "alice",
	}
	stream.PublishScanState(b, job)
	ev, ok := drainOne(t, sub)
	if !ok {
		t.Fatal("expected one event; got none")
	}
	if ev.Kind != stream.EventScanState {
		t.Errorf("Kind = %q, want %q", ev.Kind, stream.EventScanState)
	}
	var payload map[string]any
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if payload["id"] != "abc12345" {
		t.Errorf("payload id = %v", payload["id"])
	}
	if payload["state"] != "queued" {
		t.Errorf("payload state = %v", payload["state"])
	}
	if payload["operator"] != "alice" {
		t.Errorf("payload operator = %v", payload["operator"])
	}
}

// TestPublishScanState_NilBroadcasterIsNoOp.
func TestPublishScanState_NilBroadcasterIsNoOp(_ *testing.T) {
	stream.PublishScanState(nil, scanorch.Job{ID: "x"})
}

// TestPublishScanState_OmitsZeroStartedFinishedAt: queued jobs
// have zero StartedAt/FinishedAt; the wire shape should omit
// them.
func TestPublishScanState_OmitsZeroStartedFinishedAt(t *testing.T) {
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	stream.PublishScanState(b, scanorch.Job{
		ID:        "x",
		State:     scanorch.StateQueued,
		CreatedAt: time.Now().UTC(),
		Input:     "stdin",
	})
	ev, _ := drainOne(t, sub)
	var raw map[string]any
	_ = json.Unmarshal(ev.Payload, &raw)
	if _, has := raw["started_at"]; has {
		t.Error("queued payload should omit started_at")
	}
	if _, has := raw["finished_at"]; has {
		t.Error("queued payload should omit finished_at")
	}
}

// TestBroadcastingStore_Submit publishes after a successful
// Submit on the inner store.
func TestBroadcastingStore_Submit(t *testing.T) {
	inner := scanorch.NewMemoryStore()
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	wrapped := stream.NewBroadcastingStore(inner, b)
	job, err := wrapped.Submit(context.Background(),
		scanorch.SubmitRequest{Input: "stdin"}, "alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	ev, ok := drainOne(t, sub)
	if !ok {
		t.Fatal("expected an event after Submit")
	}
	if ev.Kind != stream.EventScanState {
		t.Errorf("Kind = %q", ev.Kind)
	}
	// Round-trip: the inner store has the job too.
	got, err := inner.Get(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("inner Get err = %v", err)
	}
	if got.ID != job.ID {
		t.Errorf("inner job ID = %q", got.ID)
	}
}

// TestBroadcastingStore_Transition: every successful state
// move emits.
func TestBroadcastingStore_Transition(t *testing.T) {
	inner := scanorch.NewMemoryStore()
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	wrapped := stream.NewBroadcastingStore(inner, b)
	job, _ := wrapped.Submit(context.Background(),
		scanorch.SubmitRequest{Input: "stdin"}, "alice")
	// Drain the Submit event.
	_, _ = drainOne(t, sub)
	// queued → running.
	if _, err := wrapped.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{}); err != nil {
		t.Fatalf("Transition err = %v", err)
	}
	ev, ok := drainOne(t, sub)
	if !ok {
		t.Fatal("expected an event after Transition")
	}
	var raw map[string]any
	_ = json.Unmarshal(ev.Payload, &raw)
	if raw["state"] != "running" {
		t.Errorf("payload state = %v, want running", raw["state"])
	}
}

// TestBroadcastingStore_FailedSubmitDoesNotPublish: a Submit
// that errors must not emit a misleading "this happened" event.
func TestBroadcastingStore_FailedSubmitDoesNotPublish(t *testing.T) {
	inner := scanorch.NewMemoryStore()
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	wrapped := stream.NewBroadcastingStore(inner, b)
	_, err := wrapped.Submit(context.Background(),
		scanorch.SubmitRequest{}, "alice") // empty input
	if err == nil {
		t.Fatal("expected ErrInputRequired")
	}
	if !errors.Is(err, scanorch.ErrInputRequired) {
		t.Errorf("err = %v, want ErrInputRequired", err)
	}
	if _, ok := drainOne(t, sub); ok {
		t.Error("failed Submit should not have emitted an event")
	}
}

// TestBroadcastingStore_FailedTransitionDoesNotPublish.
func TestBroadcastingStore_FailedTransitionDoesNotPublish(t *testing.T) {
	inner := scanorch.NewMemoryStore()
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	wrapped := stream.NewBroadcastingStore(inner, b)
	// Transitioning a non-existent job → ErrJobNotFound.
	_, err := wrapped.Transition(context.Background(), "no-such",
		scanorch.StateRunning, scanorch.TransitionFields{})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := drainOne(t, sub); ok {
		t.Error("failed Transition should not have emitted an event")
	}
}

// TestBroadcastingStore_GetListReadOnly: Get + List are pure
// reads and emit nothing.
func TestBroadcastingStore_GetListReadOnly(t *testing.T) {
	inner := scanorch.NewMemoryStore()
	b := stream.New(8)
	sub, cancel := b.Subscribe()
	defer cancel()
	wrapped := stream.NewBroadcastingStore(inner, b)
	job, _ := wrapped.Submit(context.Background(),
		scanorch.SubmitRequest{Input: "stdin"}, "alice")
	// Drain Submit event.
	_, _ = drainOne(t, sub)
	if _, err := wrapped.Get(context.Background(), job.ID); err != nil {
		t.Fatalf("Get err = %v", err)
	}
	if _, err := wrapped.List(context.Background(), 10); err != nil {
		t.Fatalf("List err = %v", err)
	}
	if _, ok := drainOne(t, sub); ok {
		t.Error("Get/List must not emit events")
	}
}

// TestBroadcastingStore_NilBroadcasterStillFunctional: a nil
// broadcaster makes the wrapper a transparent pass-through —
// useful for tests + dev configs that don't wire SSE.
func TestBroadcastingStore_NilBroadcasterStillFunctional(t *testing.T) {
	inner := scanorch.NewMemoryStore()
	wrapped := stream.NewBroadcastingStore(inner, nil)
	job, err := wrapped.Submit(context.Background(),
		scanorch.SubmitRequest{Input: "stdin"}, "alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, err := wrapped.Get(context.Background(), job.ID); err != nil {
		t.Fatalf("Get err = %v", err)
	}
}
