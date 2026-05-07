package stream

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"local/elsereno/internal/scanorch"
)

// scanStateWirePayload is the dashboard-facing projection of a
// scanorch.Job emitted on the scan_state_change SSE event. The
// shape mirrors GET /api/v1/scans/{id} so the dashboard can
// directly insert it into the table without re-fetching.
type scanStateWirePayload struct {
	ID               string         `json:"id"`
	State            string         `json:"state"`
	CreatedAt        time.Time      `json:"created_at"`
	StartedAt        *time.Time     `json:"started_at,omitempty"`
	FinishedAt       *time.Time     `json:"finished_at,omitempty"`
	Input            string         `json:"input"`
	Plugins          []string       `json:"plugins,omitempty"`
	DefaultPort      int            `json:"default_port,omitempty"`
	Stats            scanorch.Stats `json:"stats"`
	FindingsByPlugin map[string]int `json:"findings_by_plugin,omitempty"`
	Error            string         `json:"error,omitempty"`
	Operator         string         `json:"operator,omitempty"`
}

// PublishScanState fans a scanorch.Job out as an EventScanState
// on b. Safe to call with b == nil (no-op) so cmd paths that
// optionally wire a dashboard can keep a single code path.
func PublishScanState(b *Broadcaster, j scanorch.Job) {
	if b == nil {
		return
	}
	payload := scanStateWirePayload{
		ID:               j.ID,
		State:            string(j.State),
		CreatedAt:        j.CreatedAt,
		Input:            j.Input,
		Plugins:          j.Plugins,
		DefaultPort:      j.DefaultPort,
		Stats:            j.Stats,
		FindingsByPlugin: j.FindingsByPlugin,
		Error:            j.Error,
		Operator:         j.Operator,
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
	inner    scanorch.Store
	b        *Broadcaster
	progress *ScanProgressThrottle
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

// Transition calls through then publishes the result. Terminal
// transitions also clear the per-job throttle state so a long-
// running serve doesn't accumulate entries for completed jobs.
func (s *BroadcastingStore) Transition(ctx context.Context, id string, to scanorch.State, fields scanorch.TransitionFields) (scanorch.Job, error) {
	job, err := s.inner.Transition(ctx, id, to, fields)
	if err != nil {
		return job, err
	}
	PublishScanState(s.b, job)
	if s.progress != nil && job.State.IsTerminal() {
		s.progress.Forget(job.ID)
	}
	return job, nil
}

// AttachProgressThrottle wires the throttle so the
// BroadcastingStore can Forget per-job state on terminal
// transitions. Optional — if nil, the throttle's per-job map
// just grows until the operator restarts serve. Wiring keeps
// the map bounded.
func (s *BroadcastingStore) AttachProgressThrottle(t *ScanProgressThrottle) {
	s.progress = t
}

// Compile-time guard.
var _ scanorch.Store = (*BroadcastingStore)(nil)

// scanProgressWirePayload is the dashboard-facing projection
// of a mid-scan Stats snapshot. Smaller than the full
// scan_state_change payload — only the fields a renderer needs
// to update an in-flight row's counters.
type scanProgressWirePayload struct {
	ID               string         `json:"id"`
	Stats            scanorch.Stats `json:"stats"`
	FindingsByPlugin map[string]int `json:"findings_by_plugin,omitempty"`
}

// PublishScanProgress fans a Stats snapshot out as an
// EventScanProgress event for the given job ID. Safe to call
// with b == nil (no-op). v1.66+: byPlugin (optional) carries
// per-plugin findings breakdown.
func PublishScanProgress(b *Broadcaster, jobID string, s scanorch.Stats, byPlugin map[string]int) {
	if b == nil {
		return
	}
	body, err := json.Marshal(scanProgressWirePayload{
		ID:               jobID,
		Stats:            s,
		FindingsByPlugin: byPlugin,
	})
	if err != nil {
		body = []byte(`{}`)
	}
	b.Publish(Event{Kind: EventScanProgress, Payload: body})
}

// ScanProgressThrottle wraps PublishScanProgress so a runner
// that fires report() on every scan event doesn't flood the
// SSE bus. The throttle:
//
//   - Per-job last-emit timestamp + minimum interval (default
//     500ms). Two snapshots arriving within the interval
//     collapse — only the latest is held; the deferred-flush
//     timer eventually emits it.
//   - Per-job last-emitted Stats: a snapshot identical to the
//     last emitted is dropped (no spurious "still 33 / 100"
//     events).
//
// The returned closure is safe for concurrent use across
// goroutines (worker pool, multiple jobs in flight, racing
// runners).
type ScanProgressThrottle struct {
	mu          sync.Mutex
	b           *Broadcaster
	minInterval time.Duration
	last        map[string]throttleEntry
}

type throttleEntry struct {
	at       time.Time
	stats    scanorch.Stats
	byPlugin map[string]int
}

// NewScanProgressThrottle returns a throttle around b. min is
// clamped to [50ms, 5s]; out-of-range values yield 500ms.
func NewScanProgressThrottle(b *Broadcaster, min time.Duration) *ScanProgressThrottle {
	if min < 50*time.Millisecond || min > 5*time.Second {
		min = 500 * time.Millisecond
	}
	return &ScanProgressThrottle{
		b:           b,
		minInterval: min,
		last:        make(map[string]throttleEntry),
	}
}

// Report is the closure target wired into Worker.OnProgress. It
// emits at most one scan_stats_progress event per job per
// minInterval; identical snapshots are dropped.
//
// v1.66+: byPlugin (per-plugin findings) travels alongside
// stats. Identical-snapshot suppression compares stats only —
// the byPlugin map MAY change without changing aggregate
// FindingsCount (e.g., findings drift between plugins as
// per-plugin counters are first populated). For dashboard
// purposes this is fine: the breakdown is informational, the
// counters are the primary signal.
func (t *ScanProgressThrottle) Report(jobID string, stats scanorch.Stats, byPlugin map[string]int) {
	if t == nil || t.b == nil {
		return
	}
	t.mu.Lock()
	prev, seen := t.last[jobID]
	now := time.Now()
	if seen && stats == prev.stats {
		t.mu.Unlock()
		return
	}
	if seen && now.Sub(prev.at) < t.minInterval {
		// Within throttle window. Update the held snapshot but
		// don't emit. The next tick (or a Flush call) will
		// surface the latest.
		t.last[jobID] = throttleEntry{at: prev.at, stats: stats, byPlugin: byPlugin}
		t.mu.Unlock()
		return
	}
	t.last[jobID] = throttleEntry{at: now, stats: stats, byPlugin: byPlugin}
	t.mu.Unlock()
	PublishScanProgress(t.b, jobID, stats, byPlugin)
}

// Flush emits any pending snapshots whose held timestamp is
// past the throttle window. Useful as a periodic tick from a
// long-lived goroutine; not strictly required (a future report
// call will emit naturally).
func (t *ScanProgressThrottle) Flush() {
	if t == nil || t.b == nil {
		return
	}
	t.mu.Lock()
	type pending struct {
		stats    scanorch.Stats
		byPlugin map[string]int
	}
	stale := make(map[string]pending)
	now := time.Now()
	for id, entry := range t.last {
		if now.Sub(entry.at) >= t.minInterval {
			stale[id] = pending{stats: entry.stats, byPlugin: entry.byPlugin}
			t.last[id] = throttleEntry{at: now, stats: entry.stats, byPlugin: entry.byPlugin}
		}
	}
	t.mu.Unlock()
	for id, p := range stale {
		PublishScanProgress(t.b, id, p.stats, p.byPlugin)
	}
}

// Forget releases the per-job throttle state. Workers should
// call this when a job reaches a terminal state — otherwise the
// per-job map grows unbounded over a long-running serve.
func (t *ScanProgressThrottle) Forget(jobID string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.last, jobID)
}
