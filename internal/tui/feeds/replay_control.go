//go:build !mini

package feeds

import (
	"sync"
	"sync/atomic"
	"time"
)

// ReplayControl (v2.53+) is the shared-pointer control struct
// that lets the TUI key handler modify Replay playback at
// runtime: pause, resume, adjust rate.
//
// Concurrency: paused uses atomic.Bool + a condvar so the
// feed goroutine blocks cheaply when paused. rateBPS (basis
// points: 100 = 1.0 lines/sec) uses atomic.Int64 so the rate
// can change between any two emitted lines.
//
// Construct with NewReplayControl. The Replay struct holds a
// *ReplayControl; the TUI Model holds the same pointer.
type ReplayControl struct {
	// rateBPS is the rate in basis points (×100). 0 means
	// uncapped (no pacing).
	rateBPS atomic.Int64
	// paused: when true, the feed blocks on `cond` before
	// reading the next line.
	paused atomic.Bool
	mu     sync.Mutex
	cond   *sync.Cond
}

// NewReplayControl constructs a ReplayControl with the
// supplied initial rate (lines/sec; 0 = uncapped).
func NewReplayControl(rate float64) *ReplayControl {
	c := &ReplayControl{}
	c.cond = sync.NewCond(&c.mu)
	c.setRate(rate)
	return c
}

// setRate stores a float64 rate as basis-points.
func (c *ReplayControl) setRate(rate float64) {
	if rate < 0 {
		rate = 0
	}
	c.rateBPS.Store(int64(rate * 100))
}

// Rate returns the current rate in lines/sec.
func (c *ReplayControl) Rate() float64 {
	return float64(c.rateBPS.Load()) / 100
}

// SetRate replaces the current rate atomically. Used by the
// TUI key handler when operator hits [ / ].
func (c *ReplayControl) SetRate(rate float64) {
	c.setRate(rate)
}

// HalveRate / DoubleRate: convenient adjusters for the [ / ]
// keys. When rate is 0 (uncapped), HalveRate sets to 1.0
// (operator gets some pacing); DoubleRate is a no-op.
func (c *ReplayControl) HalveRate() {
	r := c.Rate()
	if r == 0 {
		c.SetRate(1.0)
		return
	}
	c.SetRate(r / 2)
}

// DoubleRate multiplies the current rate by 2. No-op when
// already uncapped (Rate=0) since there's nothing faster.
func (c *ReplayControl) DoubleRate() {
	r := c.Rate()
	if r == 0 {
		return // already at max
	}
	c.SetRate(r * 2)
}

// Paused reports whether playback is currently paused.
func (c *ReplayControl) Paused() bool {
	return c.paused.Load()
}

// TogglePause flips the paused state. Returns the new state.
// When unpausing, wakes any goroutine blocked on WaitIfPaused.
func (c *ReplayControl) TogglePause() bool {
	newState := !c.paused.Load()
	c.paused.Store(newState)
	if !newState {
		c.mu.Lock()
		c.cond.Broadcast()
		c.mu.Unlock()
	}
	return newState
}

// WaitIfPaused blocks until paused becomes false. Caller
// invokes this between line-reads in the feed loop.
//
// Returns true if it had to wait (was paused at entry).
// Returns false immediately if not paused. Caller uses the
// return value to decide whether to skip pacing the next
// emission (avoids a double-delay on resume).
func (c *ReplayControl) WaitIfPaused() bool {
	if !c.paused.Load() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	waited := false
	for c.paused.Load() {
		waited = true
		c.cond.Wait()
	}
	return waited
}

// PaceDelay returns the per-line sleep duration based on the
// current rate. Used by the feed loop to gate emissions.
// 0 rate → 0 duration (no pacing).
func (c *ReplayControl) PaceDelay() time.Duration {
	r := c.Rate()
	if r <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / r)
}
