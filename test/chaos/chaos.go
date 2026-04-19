//go:build chaos

package chaos

import (
	"io"
	"math/rand/v2"
	"time"
)

// Seeded is a deterministic RNG that chaos helpers share so tests
// reproduce across runs.
type Seeded struct{ R *rand.Rand }

// NewSeeded returns a *Seeded with the given seed pair. Uses
// math/rand/v2; this is fault-injection for tests, not a security
// boundary.
// #nosec G404 -- deterministic test-only PRNG
func NewSeeded(a, b uint64) *Seeded {
	return &Seeded{R: rand.New(rand.NewPCG(a, b))}
}

// RandomDropReader drops each byte with probability p (0..1). Dropped
// bytes are skipped; the Read count reflects what the caller actually
// received.
type RandomDropReader struct {
	Under io.Reader
	P     float64
	S     *Seeded
}

// Read implements io.Reader.
func (r *RandomDropReader) Read(p []byte) (int, error) {
	buf := make([]byte, len(p))
	n, err := r.Under.Read(buf)
	if n == 0 {
		return 0, err
	}
	out := 0
	for i := 0; i < n; i++ {
		if r.S.R.Float64() >= r.P {
			p[out] = buf[i]
			out++
		}
	}
	return out, err
}

// LatencyReader delays each Read by the supplied duration.
type LatencyReader struct {
	Under   io.Reader
	Latency time.Duration
}

// Read implements io.Reader.
func (r *LatencyReader) Read(p []byte) (int, error) {
	if r.Latency > 0 {
		time.Sleep(r.Latency)
	}
	return r.Under.Read(p)
}

// FlipBitsWriter flips one bit per `Every` bytes written. Useful for
// testing parser resilience.
type FlipBitsWriter struct {
	Under io.Writer
	Every int
	S     *Seeded

	counter int
}

// Write implements io.Writer.
func (w *FlipBitsWriter) Write(p []byte) (int, error) {
	out := make([]byte, len(p))
	copy(out, p)
	for i := range out {
		w.counter++
		if w.Every > 0 && w.counter%w.Every == 0 {
			bit := uint8(w.S.R.IntN(8)) // #nosec G115 -- 0..7 fits in uint8
			out[i] ^= 1 << bit
		}
	}
	return w.Under.Write(out)
}

// EarlyCloser wraps a closer and forces Close() after N bytes have
// passed through Write(). The closer is called asynchronously so the
// current Write returns cleanly; the *next* I/O observes the close.
type EarlyCloser struct {
	Under        io.Writer
	CloseAfter   int64
	Closer       io.Closer
	writtenSoFar int64
	closed       bool
}

// Write implements io.Writer.
func (w *EarlyCloser) Write(p []byte) (int, error) {
	n, err := w.Under.Write(p)
	w.writtenSoFar += int64(n)
	if !w.closed && w.writtenSoFar >= w.CloseAfter && w.Closer != nil {
		w.closed = true
		go func() { _ = w.Closer.Close() }()
	}
	return n, err
}
