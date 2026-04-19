package outbox

import (
	"context"
	"sync"
	"time"
)

// MemStore is an in-memory Store. Useful for tests and for the CLI's
// non-DB scan flow. Not durable; restart loses everything.
type MemStore struct {
	mu      sync.Mutex
	pending []*Entry
	dead    []*Entry
}

// NewMemStore returns an empty MemStore.
func NewMemStore() *MemStore { return &MemStore{} }

// Enqueue implements Store.
func (s *MemStore) Enqueue(_ context.Context, e *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.NextTry.IsZero() {
		e.NextTry = time.Now()
	}
	s.pending = append(s.pending, e)
	return nil
}

// Claim implements Store.
func (s *MemStore) Claim(_ context.Context, maxN int, now time.Time) ([]*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var claimed []*Entry
	var keep []*Entry
	for _, e := range s.pending {
		if len(claimed) < maxN && !now.Before(e.NextTry) {
			claimed = append(claimed, e)
			continue
		}
		keep = append(keep, e)
	}
	s.pending = keep
	return claimed, nil
}

// Ack implements Store.
func (s *MemStore) Ack(_ context.Context, _ *Entry) error {
	// Claim already removed the entry from `pending`.
	return nil
}

// Fail implements Store. Entries with attempts >= maxAttempts move to
// the dead-letter list; otherwise they return to the pending queue.
func (s *MemStore) Fail(_ context.Context, e *Entry, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Attempts >= maxAttempts {
		s.dead = append(s.dead, e)
		return nil
	}
	s.pending = append(s.pending, e)
	return nil
}

// Dead returns a snapshot of the dead-letter list.
func (s *MemStore) Dead() []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Entry, len(s.dead))
	copy(out, s.dead)
	return out
}

// Pending returns a snapshot of the pending queue (tests only).
func (s *MemStore) Pending() []*Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Entry, len(s.pending))
	copy(out, s.pending)
	return out
}
