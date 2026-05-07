package stream

import (
	"context"
	"encoding/json"
	"time"

	"local/elsereno/internal/scanorch"
)

// scanStateWirePayload is the dashboard-facing projection of a
// scanorch.Job emitted on the scan_state_change SSE event. The
// shape mirrors GET /api/v1/scans/{id} so the dashboard can
// directly insert it into the table without re-fetching.
type scanStateWirePayload struct {
	ID          string         `json:"id"`
	State       string         `json:"state"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	FinishedAt  *time.Time     `json:"finished_at,omitempty"`
	Input       string         `json:"input"`
	Plugins     []string       `json:"plugins,omitempty"`
	DefaultPort int            `json:"default_port,omitempty"`
	Stats       scanorch.Stats `json:"stats"`
	Error       string         `json:"error,omitempty"`
	Operator    string         `json:"operator,omitempty"`
}

// PublishScanState fans a scanorch.Job out as an EventScanState
// on b. Safe to call with b == nil (no-op) so cmd paths that
// optionally wire a dashboard can keep a single code path.
func PublishScanState(b *Broadcaster, j scanorch.Job) {
	if b == nil {
		return
	}
	payload := scanStateWirePayload{
		ID:          j.ID,
		State:       string(j.State),
		CreatedAt:   j.CreatedAt,
		Input:       j.Input,
		Plugins:     j.Plugins,
		DefaultPort: j.DefaultPort,
		Stats:       j.Stats,
		Error:       j.Error,
		Operator:    j.Operator,
	}
	if !j.StartedAt.IsZero() {
		started := j.StartedAt
		payload.StartedAt = &started
	}
	if !j.FinishedAt.IsZero() {
		finished := j.FinishedAt
		payload.FinishedAt = &finished
	}
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	b.Publish(Event{Kind: EventScanState, Payload: body})
}

// BroadcastingStore wraps a scanorch.Store and publishes a
// scan_state_change SSE event on every successful Submit or
// Transition. The wrapped store handles persistence; this
// decorator just fans the result out to the SSE bus.
//
// Composition keeps the scanorch package free of stream-
// package concerns: scanorch.Store implementations (MemoryStore,
// DBStore) don't reach for the broadcaster; cmd_serve wraps the
// chosen store with this decorator before threading it into
// APIV1Deps + Worker.
//
// Errors from the underlying store short-circuit before any
// Publish so a failed mutation never produces a misleading
// "this happened" event.
type BroadcastingStore struct {
	inner scanorch.Store
	b     *Broadcaster
}

// NewBroadcastingStore wraps inner so every successful Submit /
// Transition publishes a scan_state_change event on b. b == nil
// means publishes are no-ops; the wrapper is still useful as a
// pass-through if the operator wires it that way.
func NewBroadcastingStore(inner scanorch.Store, b *Broadcaster) *BroadcastingStore {
	return &BroadcastingStore{inner: inner, b: b}
}

// Submit calls through then publishes the queued Job.
func (s *BroadcastingStore) Submit(ctx context.Context, req scanorch.SubmitRequest, operator string) (scanorch.Job, error) {
	job, err := s.inner.Submit(ctx, req, operator)
	if err != nil {
		return job, err
	}
	PublishScanState(s.b, job)
	return job, nil
}

// Get is a pure read; no event is published.
func (s *BroadcastingStore) Get(ctx context.Context, id string) (scanorch.Job, error) {
	return s.inner.Get(ctx, id)
}

// List is a pure read; no event is published.
func (s *BroadcastingStore) List(ctx context.Context, limit int) ([]scanorch.Job, error) {
	return s.inner.List(ctx, limit)
}

// Transition calls through then publishes the result.
func (s *BroadcastingStore) Transition(ctx context.Context, id string, to scanorch.State, fields scanorch.TransitionFields) (scanorch.Job, error) {
	job, err := s.inner.Transition(ctx, id, to, fields)
	if err != nil {
		return job, err
	}
	PublishScanState(s.b, job)
	return job, nil
}

// Compile-time guard.
var _ scanorch.Store = (*BroadcastingStore)(nil)
