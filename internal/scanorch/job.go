// Package scanorch implements the scan-job orchestration core
// behind the dashboard's "trigger a scan" button. v1.58+ closes
// the F carryover from the v1.50 substantial-items batch.
//
// This package is the orchestration shell only:
//
//   - **Job model + state machine** (queued → running →
//     completed | failed). Operators submit a Job; the store
//     tracks state transitions; the dashboard polls or streams
//     state.
//   - **In-memory Store** (v1.58 chunk 1). DB-backed Store
//     lands in a future chunk; the interface lets the swap be
//     drop-in.
//   - **REST endpoints** wire-up lives in
//     `internal/web/handlers/scans.go`.
//
// Out of scope for v1.58 chunk 1 (slated for follow-up chunks):
//
//   - **Actual scanner execution**. The Job's Run() entrypoint
//     transitions queued → running → completed but doesn't yet
//     dispatch the scanner. Chunk 2 wires the scanner package
//     in.
//   - **Persistent storage**. The in-memory Store loses jobs
//     on restart; chunk 3 adds a DB-backed Store.
//   - **Cancellation flow**. ctx cancellation is plumbed but
//     the cancellation→failed transition is just-best-effort
//     for now.
//   - **Authorisation surface**. The current iteration assumes
//     the operator who hits the endpoint is already authenticated
//     by the upstream serve middleware. v1.58 chunk N+ will
//     gate scan-trigger behind a separate scope.
package scanorch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// State is the scan-job lifecycle state.
type State string

const (
	// StateQueued is the initial state on Submit. The job is
	// waiting for a worker.
	StateQueued State = "queued"
	// StateRunning means a worker has claimed the job and is
	// actively scanning.
	StateRunning State = "running"
	// StateCompleted is a terminal state; the scan finished
	// without failure (whether or not it found anything).
	StateCompleted State = "completed"
	// StateFailed is a terminal state; the scan terminated
	// with an error. The Job's Error field carries the reason.
	StateFailed State = "failed"
	// StateCancelled is a terminal state; the operator cancelled
	// the job before completion.
	StateCancelled State = "cancelled"
)

// IsTerminal reports whether the state is final (no further
// transitions). Useful for store eviction policy.
func (s State) IsTerminal() bool {
	switch s { //nolint:exhaustive // queued+running are explicitly NOT terminal; default-false is correct
	case StateCompleted, StateFailed, StateCancelled:
		return true
	}
	return false
}

// Job is one scan unit-of-work the dashboard submitted. The
// Input + Plugins + DefaultPort fields capture the scan
// parameters; Stats accumulates as the scan runs.
type Job struct {
	// ID is the canonical 16-char hex job identifier. Generated
	// by Submit; clients see it in the response.
	ID string `json:"id"`
	// State is the lifecycle state.
	State State `json:"state"`
	// CreatedAt is when Submit was called.
	CreatedAt time.Time `json:"created_at"`
	// StartedAt is when the job transitioned to StateRunning.
	// Zero until then.
	StartedAt time.Time `json:"started_at,omitempty"`
	// FinishedAt is when the job reached a terminal state.
	// Zero until then.
	FinishedAt time.Time `json:"finished_at,omitempty"`
	// Input is the scan-input descriptor (kind:value), e.g.
	// `list:targets.txt`, `stdin`, `internetdb:185.220.0.0/24`.
	Input string `json:"input"`
	// Plugins is the explicit plugin allowlist. Empty means
	// "every registered plugin" (matches the CLI default).
	Plugins []string `json:"plugins,omitempty"`
	// DefaultPort is the optional port to assume when the input
	// kind doesn't carry one (mirrors `scan --default-port`).
	DefaultPort int `json:"default_port,omitempty"`
	// Stats is the running tally of findings + targets seen.
	// Populated by the worker; empty until first transition to
	// running.
	Stats Stats `json:"stats"`
	// FindingsByPlugin is the per-plugin breakdown of
	// FindingsCount. Operator-facing — answers "which protocol
	// produced which findings" on a multi-plugin scan.
	// Populated by the runner via TransitionFields; nil until
	// the worker writes it (typically on the terminal
	// transition + on every progress callback). The map is
	// kept separate from Stats so Stats stays a comparable
	// value type for existing equality tests.
	//
	// v1.66 NOTE: this field lives in-memory only when the
	// store is the DBStore. The 00005_scan_jobs schema doesn't
	// have a column for it; v1.67 adds the migration. Until
	// then, db-mode operators see the breakdown live via the
	// scan_stats_progress SSE stream but NOT after restart.
	FindingsByPlugin map[string]int `json:"findings_by_plugin,omitempty"`
	// Error carries the failure reason for StateFailed jobs.
	// Empty for non-failed states.
	Error string `json:"error,omitempty"`
	// Operator is the identity of whoever submitted the job
	// (from upstream auth middleware). Free-form string.
	Operator string `json:"operator,omitempty"`
	// TriggeredByScheduleID (v1.92+) is the originating schedule
	// ID when this job was auto-fired by the v1.70+ Scheduler.
	// Empty for operator-submitted manual scans. The FK
	// (migration 00014) is ON DELETE SET NULL, so deleting the
	// schedule leaves the job's history intact but drops the
	// linkage (matches the v1.88 schedule-audit pattern).
	TriggeredByScheduleID string `json:"triggered_by_schedule_id,omitempty"`
}

// Stats is the running per-job counter set the worker maintains.
type Stats struct {
	// TargetsSeen is the count of targets the input has yielded.
	TargetsSeen int `json:"targets_seen"`
	// TargetsScanned is the count of targets that completed at
	// least one plugin probe.
	TargetsScanned int `json:"targets_scanned"`
	// FindingsCount is the number of findings produced.
	FindingsCount int `json:"findings_count"`
}

// SubmitRequest is the dashboard's "trigger a scan" payload. The
// JSON shape is the same on the wire — see openapi.yaml.
type SubmitRequest struct {
	Input       string   `json:"input"`
	Plugins     []string `json:"plugins,omitempty"`
	DefaultPort int      `json:"default_port,omitempty"`
}

// Sentinel errors.
var (
	// ErrInputRequired means the SubmitRequest's Input field
	// was empty.
	ErrInputRequired = errors.New("scanorch: input is required")
	// ErrJobNotFound is returned by Get when no job has the
	// requested ID.
	ErrJobNotFound = errors.New("scanorch: job not found")
	// ErrInvalidTransition means the worker tried to transition
	// from a state that doesn't permit the target. Helps catch
	// double-completion bugs in tests.
	ErrInvalidTransition = errors.New("scanorch: invalid state transition")
	// ErrJobAlreadyTerminal means the operator tried to cancel
	// a job that's already in a terminal state.
	ErrJobAlreadyTerminal = errors.New("scanorch: job is already in a terminal state")
)

// Store is the persistence interface. The v1.58 chunk-1 in-
// memory implementation lives in store_memory.go; future cycles
// add a DB-backed Store.
type Store interface {
	// Submit creates a new queued Job from req and returns it.
	// The Job's ID + CreatedAt are populated by the store.
	Submit(ctx context.Context, req SubmitRequest, operator string) (Job, error)
	// SubmitFromSchedule (v1.92+) is the scheduler-side variant
	// of Submit. It records `scheduleID` on the created job so
	// the dashboard can later list runs per schedule via the
	// v1.92 GET /schedules/{id}/runs endpoint. Empty
	// scheduleID = equivalent to Submit (no linkage).
	SubmitFromSchedule(ctx context.Context, req SubmitRequest, operator, scheduleID string) (Job, error)
	// Get returns the Job with the given ID, or ErrJobNotFound.
	Get(ctx context.Context, id string) (Job, error)
	// List returns the newest jobs first, capped at limit.
	List(ctx context.Context, limit int) ([]Job, error)
	// ListBySchedule (v1.92+) returns the newest jobs first
	// for jobs triggered by `scheduleID`, capped at limit.
	// Empty slice when the schedule has no recorded runs (or
	// never fired). Limit <= 0 → store-defined default (50).
	ListBySchedule(ctx context.Context, scheduleID string, limit int) ([]Job, error)
	// Transition moves a job between states. The worker uses
	// this to advance queued → running → completed/failed; the
	// operator uses it to cancel a queued/running job.
	// Returns ErrInvalidTransition if `to` isn't reachable from
	// the job's current state.
	Transition(ctx context.Context, id string, to State, fields TransitionFields) (Job, error)
}

// TransitionFields carries optional updates that travel with a
// state change. Worker passes Stats + FindingsByPlugin + Error;
// operator-driven cancellation passes nothing.
type TransitionFields struct {
	// Stats, if non-nil, replaces the job's Stats counters.
	Stats *Stats
	// FindingsByPlugin, if non-nil, replaces the job's
	// per-plugin findings breakdown. v1.66+.
	FindingsByPlugin map[string]int
	// Error, if non-empty, sets the Error field. Only
	// meaningful for transitions to StateFailed.
	Error string
}

// validTransitions enumerates the allowed state-machine edges.
// queued → running, queued → cancelled
// running → completed, running → failed, running → cancelled
// terminal → (no edge)
var validTransitions = map[State]map[State]bool{
	StateQueued: {
		StateRunning:   true,
		StateCancelled: true,
	},
	StateRunning: {
		StateCompleted: true,
		StateFailed:    true,
		StateCancelled: true,
	},
}

// canTransition reports whether the (from, to) edge is allowed.
func canTransition(from, to State) bool {
	row, ok := validTransitions[from]
	if !ok {
		return false
	}
	return row[to]
}

// generateID returns a 16-hex-char crypto-random job identifier.
// The randomness budget (8 bytes / 64 bits) is plenty for
// uniqueness within an operator's job history; the dashboard
// uses these as opaque path components.
func generateID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// MemoryStore is the in-memory Store implementation. Goroutine-
// safe; backed by a sync.RWMutex around a map. Bounded growth
// is the operator's responsibility — there's no eviction in
// chunk 1, but List(limit) caps the returned slice.
type MemoryStore struct {
	mu   sync.RWMutex
	jobs map[string]Job
	// order is the insertion order (newest last) for List.
	order []string
}

// NewMemoryStore returns a fresh MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{jobs: make(map[string]Job)}
}

// Submit creates a queued job from req.
func (s *MemoryStore) Submit(ctx context.Context, req SubmitRequest, operator string) (Job, error) {
	return s.SubmitFromSchedule(ctx, req, operator, "")
}

// SubmitFromSchedule (v1.92+) is Submit + records the
// originating schedule ID so the dashboard can list runs by
// schedule. Empty scheduleID → behaves identically to Submit.
func (s *MemoryStore) SubmitFromSchedule(_ context.Context, req SubmitRequest, operator, scheduleID string) (Job, error) {
	if req.Input == "" {
		return Job{}, ErrInputRequired
	}
	id, err := generateID()
	if err != nil {
		return Job{}, err
	}
	job := Job{
		ID:                    id,
		State:                 StateQueued,
		CreatedAt:             time.Now().UTC().Truncate(time.Microsecond),
		Input:                 req.Input,
		Plugins:               append([]string(nil), req.Plugins...),
		DefaultPort:           req.DefaultPort,
		Operator:              operator,
		TriggeredByScheduleID: scheduleID,
	}
	s.mu.Lock()
	s.jobs[id] = job
	s.order = append(s.order, id)
	s.mu.Unlock()
	return job, nil
}

// Get returns the job with the given ID.
func (s *MemoryStore) Get(_ context.Context, id string) (Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[id]
	if !ok {
		return Job{}, ErrJobNotFound
	}
	return job, nil
}

// List returns up to `limit` jobs, newest first.
func (s *MemoryStore) List(_ context.Context, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = 20
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Walk order from newest (back) to oldest, capping at limit.
	out := make([]Job, 0, limit)
	for i := len(s.order) - 1; i >= 0 && len(out) < limit; i-- {
		if job, ok := s.jobs[s.order[i]]; ok {
			out = append(out, job)
		}
	}
	return out, nil
}

// ListBySchedule (v1.92+) returns jobs triggered by the given
// schedule ID, newest first, capped at limit. Empty slice for
// schedules with no recorded runs (or never fired).
func (s *MemoryStore) ListBySchedule(_ context.Context, scheduleID string, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Job, 0, limit)
	for i := len(s.order) - 1; i >= 0 && len(out) < limit; i-- {
		job, ok := s.jobs[s.order[i]]
		if !ok {
			continue
		}
		if job.TriggeredByScheduleID != scheduleID {
			continue
		}
		out = append(out, job)
	}
	return out, nil
}

// Transition moves a job to the new state if the edge is valid.
func (s *MemoryStore) Transition(_ context.Context, id string, to State, fields TransitionFields) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[id]
	if !ok {
		return Job{}, ErrJobNotFound
	}
	if !canTransition(job.State, to) {
		return Job{}, ErrInvalidTransition
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	switch to { //nolint:exhaustive // StateQueued can't be a transition target (only initial state)
	case StateRunning:
		job.StartedAt = now
	case StateCompleted, StateFailed, StateCancelled:
		job.FinishedAt = now
	}
	job.State = to
	if fields.Stats != nil {
		job.Stats = *fields.Stats
	}
	if fields.FindingsByPlugin != nil {
		// Copy so caller's map isn't aliased into the store.
		copy := make(map[string]int, len(fields.FindingsByPlugin))
		for k, v := range fields.FindingsByPlugin {
			copy[k] = v
		}
		job.FindingsByPlugin = copy
	}
	if fields.Error != "" {
		job.Error = fields.Error
	}
	s.jobs[id] = job
	return job, nil
}
