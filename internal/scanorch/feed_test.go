package scanorch_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/scanorch"
)

// TestPool_FeedRunsQueuedJobs: jobs queued in the store reach the pool
// and run once each. Until 2026-10-17 serve started the pool and nothing
// submitted to it, so they stayed queued forever (PITF-094).
func TestPool_FeedRunsQueuedJobs(t *testing.T) {
	store := scanorch.NewMemoryStore()
	var mu sync.Mutex
	ran := map[string]int{}
	runner := scanorch.JobRunnerFunc(func(_ context.Context, job scanorch.Job, _ scanorch.ProgressReporter) (scanorch.Stats, map[string]int, error) {
		mu.Lock()
		ran[job.ID]++
		mu.Unlock()
		return scanorch.Stats{}, nil, nil
	})
	pool := scanorch.NewPool(&scanorch.Worker{Store: store, Runner: runner}, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool.Start(ctx)
	defer pool.Stop()

	var ids []string
	for i := 0; i < 3; i++ {
		job, err := store.Submit(ctx, scanorch.SubmitRequest{Input: "list:-"}, "op")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, job.ID)
	}
	feedCtx, stopFeed := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- pool.Feed(feedCtx, store, time.Time{}, 50*time.Millisecond) }()

	deadline := time.After(5 * time.Second)
	for {
		completed := 0
		for _, id := range ids {
			j, err := store.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if j.State == scanorch.StateCompleted {
				completed++
			}
		}
		if completed == len(ids) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d of %d queued jobs completed", completed, len(ids))
		case <-time.After(20 * time.Millisecond):
		}
	}
	// A few more ticks must not run anything twice.
	time.Sleep(200 * time.Millisecond)
	stopFeed()
	if err := <-done; err == nil {
		t.Fatal("Feed returned nil after its context was cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if ran[id] != 1 {
			t.Errorf("job %s ran %d times, want 1", id, ran[id])
		}
	}
}

// TestPool_FeedSkipsJobsQueuedBeforeStart: jobs queued before the
// feed's start time stay queued and do not run, so a backlog that
// collected while nothing ran it does not fire as a burst of scans when
// serve starts (PITF-094).
func TestPool_FeedSkipsJobsQueuedBeforeStart(t *testing.T) {
	store := scanorch.NewMemoryStore()
	var mu sync.Mutex
	ran := map[string]int{}
	runner := scanorch.JobRunnerFunc(func(_ context.Context, job scanorch.Job, _ scanorch.ProgressReporter) (scanorch.Stats, map[string]int, error) {
		mu.Lock()
		ran[job.ID]++
		mu.Unlock()
		return scanorch.Stats{}, nil, nil
	})
	pool := scanorch.NewPool(&scanorch.Worker{Store: store, Runner: runner}, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool.Start(ctx)
	defer pool.Stop()

	old, err := store.Submit(ctx, scanorch.SubmitRequest{Input: "list:-"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	start := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	fresh, err := store.Submit(ctx, scanorch.SubmitRequest{Input: "list:-"}, "op")
	if err != nil {
		t.Fatal(err)
	}
	feedCtx, stopFeed := context.WithCancel(ctx)
	defer stopFeed()
	go func() { _ = pool.Feed(feedCtx, store, start, 50*time.Millisecond) }()

	deadline := time.After(5 * time.Second)
	for {
		j, err := store.Get(ctx, fresh.ID)
		if err != nil {
			t.Fatal(err)
		}
		if j.State == scanorch.StateCompleted {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("job queued after start is %s, want completed", j.State)
		case <-time.After(20 * time.Millisecond):
		}
	}
	time.Sleep(200 * time.Millisecond)
	j, err := store.Get(ctx, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if j.State != scanorch.StateQueued || ran[old.ID] != 0 {
		t.Fatalf("job queued before start: state %s, ran %d times; want queued, 0", j.State, ran[old.ID])
	}
}
