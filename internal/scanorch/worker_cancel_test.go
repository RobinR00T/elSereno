package scanorch_test

import (
	"context"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// TestWorker_CancelStopsRunningJob: cancelling a running job in the
// store (what POST /api/v1/scans/{id}/cancel does) cancels the
// runner's context, and the job ends cancelled. Until 2026-10-17 the
// runner kept probing and the run was recorded as completed
// (PITF-094).
func TestWorker_CancelStopsRunningJob(t *testing.T) {
	store := scanorch.NewMemoryStore()
	started := make(chan struct{})
	stopped := make(chan error, 1)
	runner := scanorch.JobRunnerFunc(func(ctx context.Context, _ scanorch.Job, _ scanorch.ProgressReporter) (scanorch.Stats, map[string]int, error) {
		close(started)
		select {
		case <-ctx.Done():
			stopped <- ctx.Err()
		case <-time.After(10 * time.Second):
			stopped <- nil
		}
		return scanorch.Stats{}, nil, nil
	})
	w := &scanorch.Worker{Store: store, Runner: runner, CancelPoll: 20 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	job, err := store.Submit(ctx, scanorch.SubmitRequest{Input: "list:-"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		job scanorch.Job
		err error
	}
	done := make(chan result, 1)
	go func() {
		j, err := w.Process(ctx, job.ID)
		done <- result{j, err}
	}()
	<-started
	if _, err := store.Transition(ctx, job.ID, scanorch.StateCancelled, scanorch.TransitionFields{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stopped:
		if err == nil {
			t.Fatal("the runner's context was never cancelled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the runner kept running after the cancel")
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("Process: %v", r.err)
	}
	if r.job.State != scanorch.StateCancelled {
		t.Fatalf("final state %s, want cancelled", r.job.State)
	}
}

// hangingGetStore is a store whose Get blocks until its context ends,
// as a pgx call does when the database stops answering.
type hangingGetStore struct{ scanorch.Store }

func (h hangingGetStore) Get(ctx context.Context, _ string) (scanorch.Job, error) {
	<-ctx.Done()
	return scanorch.Job{}, ctx.Err()
}

// TestWorker_CancelWatchDoesNotHang: a store that does not answer the
// cancel watch does not hold Process once the runner is done (found by
// the re-audit of PITF-094).
func TestWorker_CancelWatchDoesNotHang(t *testing.T) {
	mem := scanorch.NewMemoryStore()
	runner := scanorch.JobRunnerFunc(func(context.Context, scanorch.Job, scanorch.ProgressReporter) (scanorch.Stats, map[string]int, error) {
		time.Sleep(100 * time.Millisecond) // long enough for a watch tick
		return scanorch.Stats{}, nil, nil
	})
	w := &scanorch.Worker{Store: hangingGetStore{mem}, Runner: runner, CancelPoll: 10 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	job, err := mem.Submit(ctx, scanorch.SubmitRequest{Input: "list:-"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.Process(ctx, job.ID)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Process hung on the cancel watch after the runner finished")
	}
}
