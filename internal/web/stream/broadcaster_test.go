package stream

import (
	"sync"
	"testing"
	"time"
)

func TestPublish_FanOut(t *testing.T) {
	b := New(16)
	ch1, c1 := b.Subscribe()
	ch2, c2 := b.Subscribe()
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
	_, cancel1 := b.Subscribe()
	_, cancel2 := b.Subscribe()
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
	ch, cancel := b.Subscribe()
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

func TestPublish_ConcurrentSafe(t *testing.T) {
	b := New(64)

	// Subscribers first: drain until their channel closes on cancel.
	const nSubs = 4
	subs := make([]func(), nSubs)
	var subWG sync.WaitGroup
	for i := 0; i < nSubs; i++ {
		ch, cancel := b.Subscribe()
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
	ch, cancel := b.Subscribe()
	defer cancel()
	before := time.Now().UTC()
	b.Publish(Event{Kind: EventRunStart})
	ev := <-ch
	after := time.Now().UTC()
	if ev.PublishedAt.Before(before) || ev.PublishedAt.After(after) {
		t.Fatalf("PublishedAt %v not between %v and %v", ev.PublishedAt, before, after)
	}
}
