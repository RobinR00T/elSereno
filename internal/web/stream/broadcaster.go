// Package stream implements the process-local event broadcaster
// that backs the dashboard's Server-Sent Events (SSE) feed.
//
// The scanner (and every other source that wants to light up the
// dashboard live) calls `Broadcaster.Publish(ev)`. Each connected
// SSE client has its own buffered channel and receives every
// published event. Slow clients are disconnected rather than
// allowed to stall the broadcaster.
package stream

import (
	"sync"
	"sync/atomic"
	"time"
)

// EventKind groups events so the UI can pick a severity chip or
// colour per kind. Values are stable strings (wire contract).
type EventKind string

// Event kinds emitted today.
const (
	// EventFinding announces a new Finding has been produced.
	EventFinding EventKind = "finding"
	// EventRunStart announces a scanner run has started.
	EventRunStart EventKind = "run_start"
	// EventRunEnd announces a scanner run has ended.
	EventRunEnd EventKind = "run_end"
	// EventAudit announces an audit-log row has been appended.
	EventAudit EventKind = "audit"
	// EventScanState announces a scan-orchestration Job has
	// changed state (queued → running, running → completed, etc.)
	// or has just been submitted. v1.63+. The dashboard's
	// renderScans() listens for this to drop its polling timer.
	EventScanState EventKind = "scan_state_change"
)

// Event is the broadcaster's unit. Payload is the JSON-encoded
// body the SSE client receives as `data:`; ID becomes the SSE
// `id:` line so reconnecting clients can ask for events since
// their last seen id.
type Event struct {
	// ID is a monotonic counter unique per process. Broadcaster
	// assigns it on Publish.
	ID int64
	// Kind is the EventKind for ui routing.
	Kind EventKind
	// Payload is the JSON-encoded body (the UI's `JSON.parse(e.data)`).
	Payload []byte
	// PublishedAt is the wall-clock timestamp at Publish time.
	PublishedAt time.Time
}

// subscriber is one SSE connection's buffered channel. Buffering
// lets a slow client tolerate a burst; once the buffer fills the
// broadcaster drops the subscriber rather than stall the rest.
type subscriber struct {
	ch      chan Event
	dropped atomic.Bool
}

// Broadcaster fans events out to every live subscriber. Safe for
// concurrent Publish + Subscribe.
type Broadcaster struct {
	mu      sync.RWMutex
	subs    map[*subscriber]struct{}
	nextID  atomic.Int64
	bufSize int
}

// New returns a Broadcaster whose subscribers each get a channel
// of capacity bufSize. 32 is a sensible default — enough to
// absorb a few-hundred-event burst from a fast scan while a slow
// browser catches up.
func New(bufSize int) *Broadcaster {
	if bufSize <= 0 {
		bufSize = 32
	}
	return &Broadcaster{
		subs:    make(map[*subscriber]struct{}),
		bufSize: bufSize,
	}
}

// Subscribe registers a fresh subscriber. The returned channel
// delivers every Event published after Subscribe returns; the
// returned cancel closes the channel + removes the subscriber.
// The channel is buffered; if a client lags more than bufSize
// events behind, the broadcaster marks it dropped and closes the
// channel.
func (b *Broadcaster) Subscribe() (<-chan Event, func()) {
	sub := &subscriber{ch: make(chan Event, b.bufSize)}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, sub)
			b.mu.Unlock()
			close(sub.ch)
		})
	}
	return sub.ch, cancel
}

// Publish dispatches ev to every subscriber. Slow subscribers
// are marked dropped without holding up the others. Returns the
// assigned event ID so callers can log it alongside whatever
// produced the event.
func (b *Broadcaster) Publish(ev Event) int64 {
	ev.ID = b.nextID.Add(1)
	if ev.PublishedAt.IsZero() {
		ev.PublishedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	// Snapshot subscribers under a read lock — minimises the
	// time holding the map while a fan-out runs.
	b.mu.RLock()
	victims := make([]*subscriber, 0, len(b.subs))
	for s := range b.subs {
		victims = append(victims, s)
	}
	b.mu.RUnlock()
	for _, s := range victims {
		if s.dropped.Load() {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// Buffer full → drop the subscriber so one slow
			// client can't stall the broadcaster. The channel
			// stays open until the handler's cancel fires.
			s.dropped.Store(true)
		}
	}
	return ev.ID
}

// Len returns the current subscriber count. Useful for a metrics
// gauge; also lets tests confirm a cancel cleaned up.
func (b *Broadcaster) Len() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
