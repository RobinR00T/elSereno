package scanner

import (
	"sync"
	"time"
)

// CircuitBreaker tracks consecutive failures per host and trips when
// the threshold is exceeded. Tripped hosts bypass the probe for
// `cooldown`; the next attempt after cooldown is a "half-open" probe
// whose outcome resets or re-arms the breaker.
type CircuitBreaker struct {
	Threshold int
	Cooldown  time.Duration

	mu     sync.Mutex
	states map[string]*breakerState
}

type breakerState struct {
	consecutiveFailures int
	openedAt            time.Time
}

// NewCircuitBreaker returns a breaker that trips after `threshold`
// consecutive failures and re-arms after `cooldown`. Zero/negative
// values fall back to sensible defaults (5 / 30s).
func NewCircuitBreaker(threshold int, cooldown time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &CircuitBreaker{
		Threshold: threshold,
		Cooldown:  cooldown,
		states:    make(map[string]*breakerState),
	}
}

// Allow reports whether a probe against host should be attempted. A
// tripped breaker returns false until cooldown has elapsed.
func (c *CircuitBreaker) Allow(host string) bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.states[host]
	if s == nil {
		return true
	}
	if s.consecutiveFailures < c.Threshold {
		return true
	}
	if time.Since(s.openedAt) >= c.Cooldown {
		// Half-open: allow one probe, reset counter to threshold-1 so
		// another failure re-trips instantly.
		s.consecutiveFailures = c.Threshold - 1
		return true
	}
	return false
}

// RecordSuccess resets the breaker's state for host.
func (c *CircuitBreaker) RecordSuccess(host string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.states, host)
}

// RecordFailure increments the breaker's counter. The breaker trips
// when the counter reaches the threshold.
func (c *CircuitBreaker) RecordFailure(host string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.states[host]
	if s == nil {
		s = &breakerState{}
		c.states[host] = s
	}
	s.consecutiveFailures++
	if s.consecutiveFailures >= c.Threshold {
		s.openedAt = time.Now()
	}
}

// TripCount returns the number of currently tripped (open) hosts. Used
// by tests and telemetry.
func (c *CircuitBreaker) TripCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.states {
		if s.consecutiveFailures >= c.Threshold &&
			time.Since(s.openedAt) < c.Cooldown {
			n++
		}
	}
	return n
}
