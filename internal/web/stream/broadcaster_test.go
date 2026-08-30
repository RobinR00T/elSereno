package stream

import (
	"sync"
	"testing"
	"time"
)

func TestPublish_FanOut(t *testing.T) {
	b := New(16)
	ch1, _, c1 := b.Subscribe()
	ch2, _, c2 := b.Subscribe()
	defer c1()
	defer c2()

	id := b.Publish(Event{Kind: EventFinding, Payload: []byte(`{"x":1}`)})
	if id != 1 {
		t.Fatalf("first ID = %d, want 1", id)
	}

	e1 := <-ch1
	e2 := <-ch2
	if e1.ID != 1 || e2.ID != 1 {
		t.Fatalf("both subscribers should see ID=1, got %d/%d", e1.ID, e2.ID)
	}
	if e1.Kind != EventFinding {
		t.Fatalf("kind mismatch")
	}
}

func TestSubscribe_LenTracksUpDown(t *testing.T) {
	b := New(8)
	if n := b.Len(); n != 0 {
		t.Fatalf("initial Len = %d, want 0", n)
	}
	_, _, cancel1 := b.Subscribe()
	_, _, cancel2 := b.Subscribe()
	if n := b.Len(); n != 2 {
		t.Fatalf("after 2 subscribes: %d", n)
	}
	cancel1()
	if n := b.Len(); n != 1 {
		t.Fatalf("after 1 cancel: %d", n)
	}
	cancel2()
	if n := b.Len(); n != 0 {
		t.Fatalf("after all cancels: %d", n)
	}
}

func TestPublish_SlowSubscriberDropped(t *testing.T) {
	b := New(2) // tiny buffer
	ch, _, cancel := b.Subscribe()
	defer cancel()
	// Don't read from ch; publish 5 events. The 3rd+ publish
	// should see the buffer full and mark the subscriber dropped.
	for i := 0; i < 5; i++ {
		b.Publish(Event{Kind: EventFinding})
	}
	// The subscriber's channel has exactly bufSize (2) events in
	// it; the rest were dropped — no panic, no block.
	var count int
	// Drain what's available with a short timeout.
	for {
		select {
		case <-ch:
			count++
		case <-time.After(50 * time.Millisecond):
			goto done
		}
	}
done:
	if count != 2 {
		t.Fatalf("slow subscriber saw %d events, want 2 (buffered) before being dropped", count)
	}
}

// TestPublish_DroppedSubscriberSignalsDone: when a subscriber is
// dropped for lagging, its done channel closes so the SSE handler can
// disconnect it instead of leaving it as a heartbeat-only zombie.
func TestPublish_DroppedSubscriberSignalsDone(t *testing.T) {
	b := New(2)
	_, done, cancel := b.Subscribe()
	defer cancel()
	// Overflow the buffer without reading, forcing the drop.
	for i := 0; i < 5; i++ {
		b.Publish(Event{Kind: EventFinding})
	}
	select {
	case <-done:
		// dropped → done closed, as expected.
	case <-time.After(time.Second):
		t.Fatal("dropped subscriber's done channel was not closed")
	}
}

// TestSubscribe_HealthyDoneStaysOpen: a subscriber that keeps up is
// never dropped, so its done channel stays open.
func TestSubscribe_HealthyDoneStaysOpen(t *testing.T) {
	b := New(8)
	ch, done, cancel := b.Subscribe()
	defer cancel()
	b.Publish(Event{Kind: EventFinding})
	<-ch // drain so the buffer never overflows
	select {
	case <-done:
		t.Fatal("healthy subscriber's done channel should stay open")
	case <-time.After(50 * time.Millisecond):
		// still open, good.
	}
}

func TestPublish_ConcurrentSafe(t *testing.T) {
	b := New(64)

	// Subscribers first: drain until their channel closes on cancel.
	const nSubs = 4
	subs := make([]func(), nSubs)
	var subWG sync.WaitGroup
	for i := 0; i < nSubs; i++ {
		ch, _, cancel := b.Subscribe()
		subs[i] = cancel
		subWG.Add(1)
		go func(c <-chan Event) {
			defer subWG.Done()
			for range c {
				// drain; loop exits when cancel closes the channel
			}
		}(ch)
	}

	// 4 producers × 250 events each = 1000 events.
	var prodWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		prodWG.Add(1)
		go func() {
			defer prodWG.Done()
			for j := 0; j < 250; j++ {
				b.Publish(Event{Kind: EventAudit})
			}
		}()
	}
	prodWG.Wait()

	// Producers are done; cancel subscribers so their drain loops
	// exit, then wait for them to finish.
	for _, c := range subs {
		c()
	}
	subWG.Wait()

	// After all cancels the broadcaster must be empty.
	if n := b.Len(); n != 0 {
		t.Fatalf("residual subscribers: %d", n)
	}
}

func TestPublish_PublishedAtSet(t *testing.T) {
	b := New(4)
	ch, _, cancel := b.Subscribe()
	defer cancel()
	// PublishedAt is microsecond-truncated (matches the
	// Postgres TIMESTAMPTZ resolution used elsewhere). Truncate
	// the bounds to the same precision so a wall-clock with a
	// non-zero nanosecond suffix doesn't push PublishedAt
	// below `before` (an artefact of truncation, not an actual
	// time-ordering bug — caught flakily on Linux CI 2026-05-12).
	before := time.Now().UTC().Truncate(time.Microsecond)
	b.Publish(Event{Kind: EventRunStart})
	ev := <-ch
	after := time.Now().UTC().Truncate(time.Microsecond)
	if ev.PublishedAt.Before(before) || ev.PublishedAt.After(after) {
		t.Fatalf("PublishedAt %v not between %v and %v", ev.PublishedAt, before, after)
	}
}

// TestPublish_ConcurrentCancelNoPanic stresses the race that used to
// panic with "send on closed channel": one goroutine publishes in a
// tight loop while many subscribers churn (Subscribe then cancel).
// The pre-fix cancel closed the data channel out from under Publish.
// Run with -race to also catch data races.
func TestPublish_ConcurrentCancelNoPanic(t *testing.T) {
	b := New(1) // tiny buffer to also exercise the buffer-full drop path
	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.Publish(Event{Kind: EventFinding, Payload: []byte(`{}`)})
			}
		}
	}()

	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				ch, _, cancel := b.Subscribe()
				select {
				case <-ch:
				default:
				}
				cancel()
			}
		}()
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	if got := b.Len(); got != 0 {
		t.Fatalf("all subscribers cancelled, want Len 0, got %d", got)
	}
}
