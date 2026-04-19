//go:build chaos

package chaos_test

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"local/elsereno/test/chaos"
)

func TestRandomDropReader(t *testing.T) {
	t.Parallel()
	src := strings.NewReader(strings.Repeat("a", 1000))
	r := &chaos.RandomDropReader{Under: src, P: 0.5, S: chaos.NewSeeded(1, 2)}
	buf := make([]byte, 2000)
	n, _ := io.ReadFull(r, buf)
	// With P=0.5, expected ~500. Loose bounds account for RNG variance.
	if n < 400 || n > 600 {
		t.Fatalf("dropped count %d out of expected [400,600]", n)
	}
}

func TestLatencyReader(t *testing.T) {
	t.Parallel()
	src := strings.NewReader("x")
	r := &chaos.LatencyReader{Under: src, Latency: 20 * time.Millisecond}
	start := time.Now()
	_, _ = io.ReadAll(r)
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("Latency was not applied")
	}
}

func TestFlipBitsWriter(t *testing.T) {
	t.Parallel()
	var sink bytes.Buffer
	w := &chaos.FlipBitsWriter{Under: &sink, Every: 4, S: chaos.NewSeeded(7, 7)}
	in := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, _ = w.Write(in)
	out := sink.Bytes()
	// Exactly 2 bytes should have had a bit flipped (every 4 of 8).
	flipped := 0
	for _, b := range out {
		if b != 0 {
			flipped++
		}
	}
	if flipped != 2 {
		t.Fatalf("expected 2 flipped bytes, got %d: % x", flipped, out)
	}
}
