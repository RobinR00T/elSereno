//go:build !mini

package feeds

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/tui"
)

// drain collects every emitted message synchronously. Run loops
// inline (no goroutines) so plain slice append is safe.
type drain struct {
	mu   sync.Mutex
	msgs []tea.Msg
}

func (d *drain) emit() func(tea.Msg) {
	return func(msg tea.Msg) {
		d.mu.Lock()
		d.msgs = append(d.msgs, msg)
		d.mu.Unlock()
	}
}

// findingFixture returns a minimal valid ndjson:v1 line.
func findingFixture(score int, proto string) string {
	return `{"schema":"ndjson:v1","run_id":"00000000-0000-0000-0000-000000000001","target_id":"00000000-0000-0000-0000-000000000002","address":"10.0.0.1","port":502,"protocol":"` +
		proto + `","severity":"high","score":` + itoa(score) +
		`,"factors":{"banner":50,"port":40},"created_at":"2026-04-29T12:00:00Z"}`
}

// itoa avoids strconv import noise in fixtures.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// TestReplayHappyPath drives 3 valid lines + asserts the FindingMsgs
// arrive in order with the expected scores.
func TestReplayHappyPath(t *testing.T) {
	src := strings.NewReader(strings.Join([]string{
		findingFixture(91, "modbus"),
		findingFixture(72, "s7"),
		findingFixture(33, "snmp"),
	}, "\n"))

	d := &drain{}
	ctx := context.Background()
	r := Replay{Path: "test"}
	if err := r.stream(ctx, src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got := len(d.msgs); got != 3 {
		t.Fatalf("emitted %d messages, want 3 (msgs: %v)", got, d.msgs)
	}
	wantScores := []int{91, 72, 33}
	for i, m := range d.msgs {
		fm, ok := m.(tui.FindingMsg)
		if !ok {
			t.Errorf("[%d] = %T, want tui.FindingMsg", i, m)
			continue
		}
		if fm.Finding.Score != wantScores[i] {
			t.Errorf("[%d] score = %d, want %d", i, fm.Finding.Score, wantScores[i])
		}
		if fm.Finding.Protocol == "" {
			t.Errorf("[%d] missing protocol", i)
		}
		if fm.Finding.CreatedAt.IsZero() {
			t.Errorf("[%d] CreatedAt zero", i)
		}
	}
}

// TestReplayMalformedLineSkipped — a bad JSON line becomes an
// AuditMsg ("skipped malformed line N: …") instead of aborting.
func TestReplayMalformedLineSkipped(t *testing.T) {
	src := strings.NewReader(strings.Join([]string{
		findingFixture(91, "modbus"),
		`{"this is not valid JSON`,
		findingFixture(50, "mms"),
	}, "\n"))

	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if got := len(d.msgs); got != 3 {
		t.Fatalf("emitted %d, want 3 (1 finding + 1 skip + 1 finding)", got)
	}
	if _, ok := d.msgs[0].(tui.FindingMsg); !ok {
		t.Errorf("[0] not a FindingMsg")
	}
	am, ok := d.msgs[1].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[1] = %T, want tui.AuditMsg", d.msgs[1])
	}
	if !strings.Contains(am.Line, "skipped malformed line 2") {
		t.Errorf("[1] audit line = %q, want 'skipped malformed line 2'", am.Line)
	}
	if _, ok := d.msgs[2].(tui.FindingMsg); !ok {
		t.Errorf("[2] not a FindingMsg")
	}
}

// TestReplayWrongSchemaSkipped — a record with the wrong schema
// is skipped + reported, not silently coerced.
func TestReplayWrongSchemaSkipped(t *testing.T) {
	src := strings.NewReader(`{"schema":"ndjson:v0","run_id":"x","target_id":"y","address":"a","port":1,"protocol":"p","severity":"low","score":1,"factors":{},"created_at":""}`)
	d := &drain{}
	_ = (Replay{Path: "test"}).stream(context.Background(), src, d.emit())
	if got := len(d.msgs); got != 1 {
		t.Fatalf("emitted %d, want 1", got)
	}
	am, ok := d.msgs[0].(tui.AuditMsg)
	if !ok {
		t.Fatalf("got %T, want tui.AuditMsg", d.msgs[0])
	}
	if !strings.Contains(am.Line, "unknown schema") {
		t.Errorf("audit line = %q, want 'unknown schema'", am.Line)
	}
}

// TestReplayContextCancel — long replay terminates promptly when
// the context is cancelled. Uses Rate to slow playback so the
// cancellation loop has lines to skip.
func TestReplayContextCancel(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = findingFixture(50, "modbus")
	}
	src := strings.NewReader(strings.Join(lines, "\n"))

	d := &drain{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := (Replay{Path: "test", Rate: 1000}).stream(ctx, src, d.emit())
	// First-line check happens before parsing, so we expect
	// context.Canceled from the loop guard.
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestReplayEmptyPath — Run rejects an empty path.
func TestReplayEmptyPath(t *testing.T) {
	r := Replay{}
	err := r.Run(context.Background(), func(tea.Msg) {})
	if err == nil || !strings.Contains(err.Error(), "empty Path") {
		t.Errorf("err = %v, want 'empty Path'", err)
	}
}

// TestReplayMissingFile — Run reports the I/O error.
func TestReplayMissingFile(t *testing.T) {
	r := Replay{Path: filepath.Join(t.TempDir(), "nonexistent.ndjson")}
	err := r.Run(context.Background(), func(tea.Msg) {})
	if err == nil || !strings.Contains(err.Error(), "open ") {
		t.Errorf("err = %v, want wrapping 'open '", err)
	}
}

// TestReplayName — the human-readable identifier includes the path.
func TestReplayName(t *testing.T) {
	r := Replay{Path: "/tmp/x.ndjson"}
	if got := r.Name(); got != "replay /tmp/x.ndjson" {
		t.Errorf("Name = %q", got)
	}
}

// TestReplayPacing — a Rate >0 introduces a per-line delay that's
// observable via wallclock. Loose check (5x slack) so this test
// stays stable on CI runners.
func TestReplayPacing(t *testing.T) {
	src := strings.NewReader(strings.Join([]string{
		findingFixture(50, "modbus"),
		findingFixture(50, "modbus"),
		findingFixture(50, "modbus"),
	}, "\n"))
	d := &drain{}
	start := time.Now()
	r := Replay{Path: "test", Rate: 50} // 50 lines/s → 20 ms/line
	if err := r.stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	elapsed := time.Since(start)
	// 3 lines × 20 ms = 60 ms minimum (a final pace tick fires
	// after the last emit). Bound only the lower edge — CI
	// schedulers can stretch the upper.
	if elapsed < 40*time.Millisecond {
		t.Errorf("pacing: elapsed=%v, want ≥40ms", elapsed)
	}
}
