package scanner_test

import (
	"testing"
	"time"

	"local/elsereno/internal/scanner"
)

func TestCircuitBreakerTripsAndCooldowns(t *testing.T) {
	t.Parallel()
	b := scanner.NewCircuitBreaker(3, 50*time.Millisecond)

	// Three failures → breaker trips.
	for i := 0; i < 3; i++ {
		if !b.Allow("h1") {
			t.Fatalf("should allow probe %d before tripping", i)
		}
		b.RecordFailure("h1")
	}
	if b.Allow("h1") {
		t.Fatal("breaker should be tripped after 3 failures")
	}
	if b.TripCount() != 1 {
		t.Fatalf("TripCount = %d, want 1", b.TripCount())
	}

	// After cooldown, half-open probe is allowed.
	time.Sleep(60 * time.Millisecond)
	if !b.Allow("h1") {
		t.Fatal("breaker should allow half-open probe after cooldown")
	}

	// Successful probe resets the breaker.
	b.RecordSuccess("h1")
	if b.TripCount() != 0 {
		t.Fatalf("after success TripCount = %d, want 0", b.TripCount())
	}
}

func TestTemporalDedupe(t *testing.T) {
	t.Parallel()
	d := scanner.NewTemporalDedupe(100 * time.Millisecond)
	now := time.Now()
	if d.Seen("k", now) {
		t.Fatal("first Seen should be false")
	}
	if !d.Seen("k", now.Add(50*time.Millisecond)) {
		t.Fatal("within window should be true")
	}
	if d.Seen("k", now.Add(200*time.Millisecond)) {
		t.Fatal("outside window should be false")
	}
}
