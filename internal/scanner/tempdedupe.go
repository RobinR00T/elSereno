package scanner

import (
	"sync"
	"time"
)

// TemporalDedupe suppresses repeated probes against the same target
// within a sliding time window. The default window is 5 minutes per
// the project brief.
type TemporalDedupe struct {
	Window time.Duration

	mu   sync.Mutex
	seen map[string]time.Time
}

// DefaultTemporalWindow is the brief's specified dedup window.
const DefaultTemporalWindow = 5 * time.Minute

// NewTemporalDedupe returns a dedupe with the supplied window. Zero
// or negative windows fall back to DefaultTemporalWindow.
func NewTemporalDedupe(window time.Duration) *TemporalDedupe {
	if window <= 0 {
		window = DefaultTemporalWindow
	}
	return &TemporalDedupe{
		Window: window,
		seen:   make(map[string]time.Time),
	}
}

// Seen returns true if key has been observed within the window. It is
// a side-effectful check: callers receive the boolean AND the map
// gets a fresh timestamp if the key had expired.
func (d *TemporalDedupe) Seen(key string, now time.Time) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	prev, ok := d.seen[key]
	if ok && now.Sub(prev) < d.Window {
		return true
	}
	d.seen[key] = now
	return false
}

// Prune drops entries older than `now - window`. Called opportunistically
// by callers to cap memory; not strictly required.
func (d *TemporalDedupe) Prune(now time.Time) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.seen {
		if now.Sub(t) >= d.Window {
			delete(d.seen, k)
		}
	}
}
