//go:build offensive

package backend

import (
	"context"
	"sync"
	"time"
)

// Mock is the default backend. It records every Deliver call
// without touching hardware. Tests + CI + dry-runs use this
// exclusively.
//
// Callers may pre-seed Mock.Script to drive specific
// dispositions for specific normalised numbers (pattern:
// longest-prefix-match). Unscripted numbers return
// DispositionPreview.
type Mock struct {
	// Script maps a normalised number PREFIX to the disposition
	// + reason that Deliver should return. An empty map means
	// every call returns DispositionPreview.
	Script map[string]Result

	mu    sync.Mutex
	calls []MockCall
}

// MockCall is a recorded Deliver invocation.
type MockCall struct {
	Number string
	At     time.Time
	Result Result
}

// NewMock constructs a Mock with an empty script.
func NewMock() *Mock {
	return &Mock{Script: map[string]Result{}}
}

// Name implements Backend.
func (m *Mock) Name() string { return "mock" }

// Deliver implements Backend. Looks up the longest-prefix match
// in Script; defaults to DispositionPreview with Reason "mock".
func (m *Mock) Deliver(ctx context.Context, number string) (Result, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return Result{
			Disposition: DispositionFailed,
			Reason:      "cancelled",
			Duration:    time.Since(start),
		}, err
	}
	res := m.lookup(number)
	res.Duration = time.Since(start)
	m.mu.Lock()
	m.calls = append(m.calls, MockCall{Number: number, At: start, Result: res})
	m.mu.Unlock()
	return res, nil
}

// Close implements Backend. No-op for the mock.
func (m *Mock) Close() error { return nil }

// Calls returns a copy of the recorded calls for tests /
// inspection. Not part of the Backend interface.
func (m *Mock) Calls() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MockCall, len(m.calls))
	copy(out, m.calls)
	return out
}

// lookup returns the scripted Result for the longest matching
// prefix in Script, or a preview default.
func (m *Mock) lookup(number string) Result {
	var best Result
	var bestLen int
	for prefix, res := range m.Script {
		if len(prefix) > bestLen && hasPrefix(number, prefix) {
			best = res
			bestLen = len(prefix)
		}
	}
	if bestLen == 0 {
		return Result{
			Disposition: DispositionPreview,
			Reason:      "mock",
		}
	}
	return best
}

// hasPrefix is a tiny wrapper so we don't pull `strings` for
// one call.
func hasPrefix(s, p string) bool {
	if len(p) > len(s) {
		return false
	}
	return s[:len(p)] == p
}
