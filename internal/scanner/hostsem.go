package scanner

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// hostSemaphore gates per-host concurrency. Each host gets its own
// Weighted semaphore created on first use and garbage-collected when
// its counter returns to zero (no explicit cleanup; the scanner's
// lifetime is bounded per Run).
type hostSemaphore struct {
	mu      sync.Mutex
	cap     int
	holders map[string]*semaphore.Weighted
}

func newHostSemaphore(cap int) *hostSemaphore {
	if cap < 1 {
		cap = 1
	}
	return &hostSemaphore{
		cap:     cap,
		holders: make(map[string]*semaphore.Weighted),
	}
}

func (h *hostSemaphore) Acquire(ctx context.Context, host string) error {
	return h.sem(host).Acquire(ctx, 1)
}

func (h *hostSemaphore) Release(host string) {
	h.sem(host).Release(1)
}

func (h *hostSemaphore) sem(host string) *semaphore.Weighted {
	h.mu.Lock()
	defer h.mu.Unlock()
	sem, ok := h.holders[host]
	if !ok {
		sem = semaphore.NewWeighted(int64(h.cap))
		h.holders[host] = sem
	}
	return sem
}
