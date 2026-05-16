//go:build offensive

package dial_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/audit"
	"local/elsereno/offensive/dial"
)

// openWardial wires an audit.FileWriter in t.TempDir + returns a
// Wardial ready to Run. Mirrors batch_test.openBatch.
func openWardial(t *testing.T) *dial.Wardial {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return &dial.Wardial{
		Writer:    w,
		Actor:     "ci",
		Operation: "dial_wardial_test",
	}
}

// TestWardial_RangeExpand: --range mode expands to 5 numbers,
// all classify as `allow`.
func TestWardial_RangeExpand(t *testing.T) {
	w := openWardial(t)
	results, err := w.Run(context.Background(), "555-0100..555-0104", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("results = %d, want 5", len(results))
	}
	for _, r := range results {
		if r.Decision != "allow" {
			t.Errorf("decision = %q, want allow (raw=%s)", r.Decision, r.Raw)
		}
	}
}

// TestWardial_ConcurrentWorkers: 50 numbers through 4 workers
// — all classified, order preserved by index.
func TestWardial_ConcurrentWorkers(t *testing.T) {
	w := openWardial(t)
	w.Workers = 4
	results, err := w.Run(context.Background(), "555-0000..555-0049", nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 50 {
		t.Fatalf("results = %d, want 50", len(results))
	}
	// Order should match expansion: results[0] = first number.
	if !strings.HasSuffix(results[0].Raw, "0000") {
		t.Errorf("results[0] = %q, want suffix 0000", results[0].Raw)
	}
	if !strings.HasSuffix(results[49].Raw, "0049") {
		t.Errorf("results[49] = %q, want suffix 0049", results[49].Raw)
	}
}

// TestWardial_RateLimit: 3 numbers @ 10/sec (100ms gap) takes
// at least 200ms (2 gaps between 3 dispatches).
func TestWardial_RateLimit(t *testing.T) {
	w := openWardial(t)
	w.RatePerSecond = 10 // 100ms per dispatch
	start := time.Now()
	_, err := w.Run(context.Background(), "555-0000..555-0002", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// 2 gaps of 100ms = 200ms minimum. Allow some scheduler slack.
	if elapsed < 150*time.Millisecond {
		t.Errorf("elapsed = %v, want >= 150ms (rate-limit not honoured)", elapsed)
	}
}

// TestWardial_CheckpointResume: first run classifies 3
// numbers + writes checkpoint; second run with same checkpoint
// skips them (returns empty results).
func TestWardial_CheckpointResume(t *testing.T) {
	w := openWardial(t)
	ckpt := filepath.Join(t.TempDir(), "checkpoint")
	w.CheckpointPath = ckpt

	// First run: 3 numbers should classify.
	r1, err := w.Run(context.Background(), "555-0000..555-0002", nil)
	if err != nil {
		t.Fatalf("first run err: %v", err)
	}
	if len(r1) != 3 {
		t.Errorf("first run results = %d, want 3", len(r1))
	}

	// Confirm checkpoint has 3 lines.
	data, err := os.ReadFile(ckpt) // #nosec G304 — test fixture.
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Errorf("checkpoint lines = %d, want 3 (%v)", len(lines), lines)
	}

	// Second run: same range, same checkpoint — should skip
	// all 3.
	r2, err := w.Run(context.Background(), "555-0000..555-0002", nil)
	if err != nil {
		t.Fatalf("second run err: %v", err)
	}
	if len(r2) != 0 {
		t.Errorf("second run results = %d, want 0 (checkpoint skip)", len(r2))
	}
}

// TestWardial_NoWriter: missing audit Writer → ErrWardialNoWriter.
func TestWardial_NoWriter(t *testing.T) {
	w := &dial.Wardial{}
	_, err := w.Run(context.Background(), "555-0000..555-0001", nil)
	if err == nil {
		t.Fatal("expected ErrWardialNoWriter")
	}
}

// TestWardial_WorkersClamp: workers > MaxWorkers clamps down.
func TestWardial_WorkersClamp(t *testing.T) {
	w := openWardial(t)
	w.Workers = 999 // way over MaxWorkers
	// Should still classify normally — the clamp happens
	// silently inside Run.
	_, err := w.Run(context.Background(), "555-0000..555-0003", nil)
	if err != nil {
		t.Errorf("clamped run err: %v", err)
	}
}
