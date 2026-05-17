//go:build !mini

package feeds_test

import (
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/tui/feeds"
)

// TestReplayControl_RateBasics: SetRate / Rate roundtrip.
func TestReplayControl_RateBasics(t *testing.T) {
	c := feeds.NewReplayControl(0)
	if c.Rate() != 0 {
		t.Errorf("initial rate = %f, want 0", c.Rate())
	}
	c.SetRate(5.0)
	if c.Rate() != 5.0 {
		t.Errorf("after SetRate(5) Rate = %f", c.Rate())
	}
}

// TestReplayControl_HalveDouble: rate adjusters.
func TestReplayControl_HalveDouble(t *testing.T) {
	c := feeds.NewReplayControl(4.0)
	c.HalveRate()
	if c.Rate() != 2.0 {
		t.Errorf("after HalveRate from 4 → %f, want 2", c.Rate())
	}
	c.DoubleRate()
	if c.Rate() != 4.0 {
		t.Errorf("after DoubleRate from 2 → %f, want 4", c.Rate())
	}
}

// TestReplayControl_HalveFromUncapped: halving uncapped (0)
// gives 1.0 (operator gets some pacing).
func TestReplayControl_HalveFromUncapped(t *testing.T) {
	c := feeds.NewReplayControl(0)
	c.HalveRate()
	if c.Rate() != 1.0 {
		t.Errorf("halve from 0 → %f, want 1.0", c.Rate())
	}
}

// TestReplayControl_DoubleAtUncapped: double from 0 is a
// no-op (already max).
func TestReplayControl_DoubleAtUncapped(t *testing.T) {
	c := feeds.NewReplayControl(0)
	c.DoubleRate()
	if c.Rate() != 0 {
		t.Errorf("double from 0 → %f, want 0 (no-op)", c.Rate())
	}
}

// TestReplayControl_PauseToggle: TogglePause flips + reports.
func TestReplayControl_PauseToggle(t *testing.T) {
	c := feeds.NewReplayControl(0)
	if c.Paused() {
		t.Error("new control should not start paused")
	}
	if !c.TogglePause() {
		t.Error("TogglePause from false should return true")
	}
	if !c.Paused() {
		t.Error("Paused() should reflect toggled state")
	}
	if c.TogglePause() {
		t.Error("second TogglePause should return false")
	}
}

// TestReplayControl_WaitBlocks: WaitIfPaused blocks until
// TogglePause unsets the flag from another goroutine.
func TestReplayControl_WaitBlocks(t *testing.T) {
	c := feeds.NewReplayControl(0)
	c.TogglePause() // pause
	var wg sync.WaitGroup
	wg.Add(1)
	released := false
	go func() {
		defer wg.Done()
		c.WaitIfPaused()
		released = true
	}()
	// Wait briefly; goroutine should still be blocked.
	time.Sleep(10 * time.Millisecond)
	if released {
		t.Error("WaitIfPaused returned without unpause")
	}
	c.TogglePause() // unpause
	// Wait for goroutine to release.
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
		// OK
	case <-time.After(time.Second):
		t.Fatal("WaitIfPaused did not return within 1s after unpause")
	}
	if !released {
		t.Error("released flag still false after unpause")
	}
}

// TestReplayControl_PaceDelay: rate → duration conversion.
func TestReplayControl_PaceDelay(t *testing.T) {
	c := feeds.NewReplayControl(10) // 10/sec → 100ms
	if got := c.PaceDelay(); got != 100*time.Millisecond {
		t.Errorf("PaceDelay = %v, want 100ms", got)
	}
	c.SetRate(0)
	if got := c.PaceDelay(); got != 0 {
		t.Errorf("PaceDelay at uncapped = %v, want 0", got)
	}
}
