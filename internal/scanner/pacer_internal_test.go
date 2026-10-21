package scanner

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a simulated clock: sleep advances it instead of waiting.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	slept  []time.Duration
	failOn int // sleep number (1-based) that returns context.Canceled
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slept = append(c.slept, d)
	if c.failOn > 0 && len(c.slept) == c.failOn {
		return context.Canceled
	}
	c.t = c.t.Add(d)
	return nil
}

func pacerWithClock(maxPerHost int, interval time.Duration) (*HostPacer, *fakeClock) {
	p := NewHostPacer(maxPerHost, interval)
	c := &fakeClock{t: time.Date(2026, 10, 21, 22, 0, 0, 0, time.UTC)}
	p.now, p.sleep = c.now, c.sleep
	return p, c
}

func TestHostPacerSpacesStartsOnOneHost(t *testing.T) {
	t.Parallel()
	p, c := pacerWithClock(1, time.Second)
	t0 := c.now()
	var starts []time.Duration
	for i := 0; i < 3; i++ {
		release, err := p.Acquire(context.Background(), "10.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		starts = append(starts, c.now().Sub(t0))
		release()
	}
	want := []time.Duration{0, time.Second, 2 * time.Second}
	for i := range want {
		if starts[i] != want[i] {
			t.Fatalf("start %d at %v, want %v (all %v)", i, starts[i], want[i], starts)
		}
	}
}

func TestHostPacerDoesNotPauseOtherHosts(t *testing.T) {
	t.Parallel()
	p, c := pacerWithClock(1, 10*time.Second)
	for _, h := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		release, err := p.Acquire(context.Background(), h)
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if len(c.slept) != 0 {
		t.Fatalf("first probe on each host slept %v; want no pause", c.slept)
	}
}

func TestHostPacerIntervalAlreadyElapsed(t *testing.T) {
	t.Parallel()
	p, c := pacerWithClock(1, time.Second)
	release, _ := p.Acquire(context.Background(), "h")
	release()
	c.t = c.t.Add(5 * time.Second) // the probe itself took longer than the interval
	release, _ = p.Acquire(context.Background(), "h")
	release()
	if len(c.slept) != 0 {
		t.Fatalf("slept %v after the interval had passed", c.slept)
	}
}

func TestHostPacerSpacesConcurrentHolders(t *testing.T) {
	t.Parallel()
	// Two slots per host: the second holder still waits the interval
	// after the first one's start.
	p, c := pacerWithClock(2, 3*time.Second)
	r1, _ := p.Acquire(context.Background(), "h")
	r2, _ := p.Acquire(context.Background(), "h")
	defer r1()
	defer r2()
	if len(c.slept) != 1 || c.slept[0] != 3*time.Second {
		t.Fatalf("slept %v, want one 3s pause", c.slept)
	}
}

func TestHostPacerCapsConcurrencyPerHost(t *testing.T) {
	t.Parallel()
	p := NewHostPacer(2, 0)
	var inFlight, peak atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := p.Acquire(context.Background(), "h")
			if err != nil {
				t.Error(err)
				return
			}
			n := inFlight.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			inFlight.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if got := peak.Load(); got != 2 {
		t.Fatalf("peak in flight on one host = %d, want 2", got)
	}
}

func TestHostPacerCancelledWaitFreesSlot(t *testing.T) {
	t.Parallel()
	p, c := pacerWithClock(1, time.Second)
	release, _ := p.Acquire(context.Background(), "h")
	release()
	c.failOn = 1
	if _, err := p.Acquire(context.Background(), "h"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// The slot was given back: a third acquire does not block.
	done := make(chan struct{})
	go func() {
		r, err := p.Acquire(context.Background(), "h")
		if err == nil {
			r()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slot leaked: acquire after a cancelled wait blocked")
	}
}

func TestNewHostPacerClampsValues(t *testing.T) {
	t.Parallel()
	p := NewHostPacer(0, -time.Second)
	if p.MaxPerHost() != 1 || p.MinInterval() != 0 {
		t.Fatalf("got %d/%v, want 1/0", p.MaxPerHost(), p.MinInterval())
	}
}
