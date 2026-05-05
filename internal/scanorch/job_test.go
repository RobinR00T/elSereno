package scanorch_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

func newReq(input string) scanorch.SubmitRequest {
	return scanorch.SubmitRequest{Input: input, Plugins: []string{"modbus"}, DefaultPort: 502}
}

// TestSubmit_Happy: queued job round-trip.
func TestSubmit_Happy(t *testing.T) {
	s := scanorch.NewMemoryStore()
	job, err := s.Submit(context.Background(), newReq("list:targets.txt"), "alice")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if job.State != scanorch.StateQueued {
		t.Errorf("State = %q, want %q", job.State, scanorch.StateQueued)
	}
	if len(job.ID) != 16 {
		t.Errorf("ID = %q (len %d), want 16-char hex", job.ID, len(job.ID))
	}
	if job.Operator != "alice" {
		t.Errorf("Operator = %q", job.Operator)
	}
	if job.Input != "list:targets.txt" {
		t.Errorf("Input = %q", job.Input)
	}
	if job.CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be populated")
	}
}

// TestSubmit_InputRequired refuses empty input.
func TestSubmit_InputRequired(t *testing.T) {
	s := scanorch.NewMemoryStore()
	_, err := s.Submit(context.Background(), scanorch.SubmitRequest{}, "alice")
	if !errors.Is(err, scanorch.ErrInputRequired) {
		t.Errorf("err = %v, want ErrInputRequired", err)
	}
}

// TestGet_NotFound returns the sentinel.
func TestGet_NotFound(t *testing.T) {
	s := scanorch.NewMemoryStore()
	_, err := s.Get(context.Background(), "nonexistent")
	if !errors.Is(err, scanorch.ErrJobNotFound) {
		t.Errorf("err = %v, want ErrJobNotFound", err)
	}
}

// TestTransition_QueuedToRunning advances the state and stamps
// StartedAt.
func TestTransition_QueuedToRunning(t *testing.T) {
	s := scanorch.NewMemoryStore()
	job, _ := s.Submit(context.Background(), newReq("stdin"), "alice")
	moved, err := s.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if moved.State != scanorch.StateRunning {
		t.Errorf("State = %q", moved.State)
	}
	if moved.StartedAt.IsZero() {
		t.Errorf("StartedAt should be populated")
	}
}

// TestTransition_RunningToCompleted stamps FinishedAt + Stats.
func TestTransition_RunningToCompleted(t *testing.T) {
	s := scanorch.NewMemoryStore()
	job, _ := s.Submit(context.Background(), newReq("stdin"), "alice")
	_, _ = s.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	stats := scanorch.Stats{TargetsSeen: 100, TargetsScanned: 100, FindingsCount: 5}
	moved, err := s.Transition(context.Background(), job.ID, scanorch.StateCompleted, scanorch.TransitionFields{Stats: &stats})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if moved.State != scanorch.StateCompleted {
		t.Errorf("State = %q", moved.State)
	}
	if moved.FinishedAt.IsZero() {
		t.Errorf("FinishedAt should be populated")
	}
	if moved.Stats != stats {
		t.Errorf("Stats = %+v, want %+v", moved.Stats, stats)
	}
}

// TestTransition_RunningToFailed sets Error.
func TestTransition_RunningToFailed(t *testing.T) {
	s := scanorch.NewMemoryStore()
	job, _ := s.Submit(context.Background(), newReq("stdin"), "alice")
	_, _ = s.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	moved, err := s.Transition(context.Background(), job.ID, scanorch.StateFailed, scanorch.TransitionFields{Error: "input file not found"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if moved.State != scanorch.StateFailed {
		t.Errorf("State = %q", moved.State)
	}
	if moved.Error != "input file not found" {
		t.Errorf("Error = %q", moved.Error)
	}
}

// TestTransition_QueuedToCancelled is allowed.
func TestTransition_QueuedToCancelled(t *testing.T) {
	s := scanorch.NewMemoryStore()
	job, _ := s.Submit(context.Background(), newReq("stdin"), "alice")
	moved, err := s.Transition(context.Background(), job.ID, scanorch.StateCancelled, scanorch.TransitionFields{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if moved.State != scanorch.StateCancelled {
		t.Errorf("State = %q", moved.State)
	}
}

// TestTransition_InvalidEdge: completed → running refuses.
func TestTransition_InvalidEdge(t *testing.T) {
	s := scanorch.NewMemoryStore()
	job, _ := s.Submit(context.Background(), newReq("stdin"), "alice")
	_, _ = s.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	_, _ = s.Transition(context.Background(), job.ID, scanorch.StateCompleted, scanorch.TransitionFields{})
	// Already completed; can't go back to running.
	_, err := s.Transition(context.Background(), job.ID, scanorch.StateRunning, scanorch.TransitionFields{})
	if !errors.Is(err, scanorch.ErrInvalidTransition) {
		t.Errorf("err = %v, want ErrInvalidTransition", err)
	}
}

// TestTransition_NotFound returns the sentinel.
func TestTransition_NotFound(t *testing.T) {
	s := scanorch.NewMemoryStore()
	_, err := s.Transition(context.Background(), "no-such-id", scanorch.StateRunning, scanorch.TransitionFields{})
	if !errors.Is(err, scanorch.ErrJobNotFound) {
		t.Errorf("err = %v, want ErrJobNotFound", err)
	}
}

// TestList_NewestFirst returns jobs in descending CreatedAt
// order (insertion order).
func TestList_NewestFirst(t *testing.T) {
	s := scanorch.NewMemoryStore()
	for i := 0; i < 5; i++ {
		_, _ = s.Submit(context.Background(), newReq("stdin"), "alice")
		// Tiny pause to ensure distinct CreatedAt clocks (only
		// strictly necessary if two Submits collide on the
		// microsecond truncation, but free insurance).
		time.Sleep(time.Microsecond)
	}
	jobs, err := s.List(context.Background(), 10)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(jobs) != 5 {
		t.Fatalf("got %d jobs, want 5", len(jobs))
	}
	for i := 1; i < len(jobs); i++ {
		if jobs[i-1].CreatedAt.Before(jobs[i].CreatedAt) {
			t.Errorf("jobs not in newest-first order at index %d", i)
		}
	}
}

// TestList_LimitClamp ensures negative/zero limit clamps to 20.
func TestList_LimitClamp(t *testing.T) {
	s := scanorch.NewMemoryStore()
	for i := 0; i < 30; i++ {
		_, _ = s.Submit(context.Background(), newReq("stdin"), "alice")
	}
	jobs, _ := s.List(context.Background(), 0)
	if len(jobs) != 20 {
		t.Errorf("limit=0 returned %d jobs, want 20 (default)", len(jobs))
	}
	jobs, _ = s.List(context.Background(), 5)
	if len(jobs) != 5 {
		t.Errorf("limit=5 returned %d jobs", len(jobs))
	}
}

// TestStateIsTerminal pins the terminal-state set.
func TestStateIsTerminal(t *testing.T) {
	for _, tc := range []struct {
		state    scanorch.State
		expected bool
	}{
		{scanorch.StateQueued, false},
		{scanorch.StateRunning, false},
		{scanorch.StateCompleted, true},
		{scanorch.StateFailed, true},
		{scanorch.StateCancelled, true},
	} {
		if got := tc.state.IsTerminal(); got != tc.expected {
			t.Errorf("State(%q).IsTerminal() = %v, want %v", tc.state, got, tc.expected)
		}
	}
}

// TestSubmit_GeneratesUniqueIDs runs many concurrent Submits and
// verifies no ID collision. Goroutine-safety pinning.
func TestSubmit_GeneratesUniqueIDs(t *testing.T) {
	s := scanorch.NewMemoryStore()
	const N = 100
	var wg sync.WaitGroup
	ids := make([]string, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			job, err := s.Submit(context.Background(), newReq("stdin"), "alice")
			if err != nil {
				t.Errorf("Submit err = %v", err)
				return
			}
			ids[idx] = job.ID
		}(i)
	}
	wg.Wait()
	seen := make(map[string]bool, N)
	for _, id := range ids {
		if id == "" {
			continue
		}
		if seen[id] {
			t.Errorf("duplicate ID: %s", id)
		}
		seen[id] = true
	}
	if len(seen) != N {
		t.Errorf("got %d unique IDs, want %d", len(seen), N)
	}
}
