package outbox_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"local/elsereno/internal/outbox"
)

func TestWorkerSuccessAcks(t *testing.T) {
	t.Parallel()
	s := outbox.NewMemStore()
	_ = s.Enqueue(context.Background(), &outbox.Entry{ID: "a", Kind: "test", Payload: []byte("x")})

	var delivered atomic.Int32
	w := outbox.NewWorker(s, func(_ context.Context, _ *outbox.Entry) error {
		delivered.Add(1)
		return nil
	})
	w.PollInterval = 5 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)

	if delivered.Load() == 0 {
		t.Fatal("entry never delivered")
	}
	if len(s.Dead()) != 0 {
		t.Fatalf("dead=%d, want 0", len(s.Dead()))
	}
}

func TestWorkerPermanentFailureMovesToDead(t *testing.T) {
	t.Parallel()
	s := outbox.NewMemStore()
	_ = s.Enqueue(context.Background(), &outbox.Entry{ID: "a", Kind: "test"})

	w := outbox.NewWorker(s, func(_ context.Context, _ *outbox.Entry) error {
		return errors.Join(outbox.ErrPermanent, errors.New("nope"))
	})
	w.PollInterval = 5 * time.Millisecond
	w.MaxAttempts = 10

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)

	if got := len(s.Dead()); got != 1 {
		t.Fatalf("dead=%d, want 1", got)
	}
}

func TestWorkerRetriesThenDeadLetters(t *testing.T) {
	t.Parallel()
	s := outbox.NewMemStore()
	_ = s.Enqueue(context.Background(), &outbox.Entry{ID: "a", Kind: "test"})

	var attempts atomic.Int32
	w := outbox.NewWorker(s, func(_ context.Context, _ *outbox.Entry) error {
		attempts.Add(1)
		return errors.New("transient")
	})
	w.PollInterval = 1 * time.Millisecond
	w.BaseBackoff = 1 * time.Millisecond
	w.MaxBackoff = 5 * time.Millisecond
	w.MaxAttempts = 3

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = w.Run(ctx)

	if got := len(s.Dead()); got != 1 {
		t.Fatalf("dead=%d after exhausting retries, want 1", got)
	}
	if a := attempts.Load(); a < 3 {
		t.Fatalf("attempts=%d, want >=3", a)
	}
}
