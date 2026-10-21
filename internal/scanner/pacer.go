package scanner

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// HostPacer bounds how hard one host is hit: at most MaxPerHost probes
// in flight against it, and at least MinInterval between the start of
// one probe and the start of the next one against it. It is shared by
// every run of a command (each plugin of a scan, every port of a
// discover sweep), so a host sees the same pace whichever plugin or
// port comes next. Hosts are keyed by address string.
type HostPacer struct {
	maxPerHost  int
	minInterval time.Duration

	mu    sync.Mutex
	hosts map[string]*hostPace

	// now and sleep are injectable for tests (simulated clock).
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

type hostPace struct {
	sem *semaphore.Weighted
	// next is the earliest start time of the next probe on this host.
	next time.Time
}

// NewHostPacer returns a pacer allowing maxPerHost concurrent probes
// per host (values below 1 mean 1) with minInterval between probe
// starts on the same host (0 or less means no pause).
func NewHostPacer(maxPerHost int, minInterval time.Duration) *HostPacer {
	if maxPerHost < 1 {
		maxPerHost = 1
	}
	if minInterval < 0 {
		minInterval = 0
	}
	return &HostPacer{
		maxPerHost:  maxPerHost,
		minInterval: minInterval,
		hosts:       make(map[string]*hostPace),
		now:         time.Now,
		sleep:       sleepCtx,
	}
}

// MaxPerHost reports the per-host concurrency cap.
func (p *HostPacer) MaxPerHost() int { return p.maxPerHost }

// MinInterval reports the minimum gap between probe starts on a host.
func (p *HostPacer) MinInterval() time.Duration { return p.minInterval }

// Acquire blocks until a probe against host may start: a per-host slot
// is free and MinInterval has passed since the previous start on that
// host. The caller must call the returned release when the probe ends.
// It returns ctx's error if ctx ends first, holding nothing.
func (p *HostPacer) Acquire(ctx context.Context, host string) (func(), error) {
	hp := p.host(host)
	if err := hp.sem.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	release := func() { hp.sem.Release(1) }
	if p.minInterval <= 0 {
		return release, nil
	}
	// Reserve the next start slot under the lock, then wait for it
	// outside the lock, so concurrent holders of the same host (with
	// MaxPerHost > 1) are spaced MinInterval apart too.
	p.mu.Lock()
	now := p.now()
	start := hp.next
	if start.Before(now) {
		start = now
	}
	hp.next = start.Add(p.minInterval)
	p.mu.Unlock()
	if wait := start.Sub(now); wait > 0 {
		if err := p.sleep(ctx, wait); err != nil {
			release()
			return nil, err
		}
	}
	return release, nil
}

func (p *HostPacer) host(host string) *hostPace {
	p.mu.Lock()
	defer p.mu.Unlock()
	hp, ok := p.hosts[host]
	if !ok {
		hp = &hostPace{sem: semaphore.NewWeighted(int64(p.maxPerHost))}
		p.hosts[host] = hp
	}
	return hp
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
