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
	// EventScanProgress announces a mid-run Stats snapshot for
	// a running scan-orchestration Job. v1.65+. The publisher
	// throttles so a 100k-target scan doesn't flood the SSE
	// bus.
	EventScanProgress EventKind = "scan_stats_progress"
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
	ch chan Event
	// done is closed exactly once, by Publish, when this subscriber is
	// dropped for lagging. It is a close-only channel (never sent to),
	// so closing it under the read lock races nothing; the SSE handler
	// selects on it and ends the response so the client reconnects
	// fresh instead of sitting on a stream that only gets heartbeats.
	done    chan struct{}
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

// Subscribe registers a fresh subscriber. It returns the event
// channel, a `dropped` channel that closes if the broadcaster drops
// this subscriber for lagging (so the caller can end its stream), and
// a cancel that closes the event channel + removes the subscriber. The
// event channel is buffered; if a client lags more than bufSize events
// behind, the broadcaster marks it dropped, closes `dropped`, and
// stops delivering. The event channel itself is closed by cancel, not
// by the drop.
func (b *Broadcaster) Subscribe() (<-chan Event, <-chan struct{}, func()) {
	sub := &subscriber{ch: make(chan Event, b.bufSize), done: make(chan struct{})}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, sub)
			// Close under the write lock so it is mutually exclusive
			// with Publish's send, which holds the read lock. The
			// RWMutex is what makes close-vs-send safe; closing after
			// releasing the lock (the earlier code) raced Publish and
			// panicked with "send on closed channel".
			close(sub.ch)
			b.mu.Unlock()
		})
	}
	return sub.ch, sub.done, cancel
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
	// Hold the read lock across the whole fan-out. The send is
	// non-blocking (select default), so a slow client cannot stall
	// the broadcaster even while the lock is held; and because cancel
	// closes each channel under the write lock, the RWMutex guarantees
	// a send never races a close.
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if s.dropped.Load() {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// Buffer full → drop the subscriber so one slow client
			// can't stall the broadcaster. Signal the handler to
			// disconnect (so its client reconnects fresh) by closing
			// `done`. CAS ensures exactly one Publish closes it; `done`
			// is close-only, so closing it under the read lock races
			// nothing. The event channel stays open until cancel fires.
			if s.dropped.CompareAndSwap(false, true) {
				close(s.done)
			}
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
