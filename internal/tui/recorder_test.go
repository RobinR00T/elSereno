//go:build !mini

package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
)

// nopWriteCloser wraps a bytes.Buffer with a no-op Close so
// the recorder can own the "lifecycle" without us worrying
// about file ops in unit tests.
type nopWriteCloser struct {
	*bytes.Buffer
}

func (nopWriteCloser) Close() error { return nil }

// TestRecorder_Tee_FindingMsg pins the on-disk shape for
// findings: the JSON line carries schema + ts + type +
// finding payload.
func TestRecorder_Tee_FindingMsg(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	r.now = func() time.Time { return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC) }

	emit := r.Tee(func(_ tea.Msg) {})
	emit(FindingMsg{Finding: core.Finding{Score: 90, Protocol: "modbus"}})

	var got recordEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, buf.String())
	}
	if got.Schema != recordSchema {
		t.Errorf("schema = %q", got.Schema)
	}
	if got.Type != "finding" {
		t.Errorf("type = %q, want finding", got.Type)
	}
	if got.TS != "2026-05-04T12:00:00Z" {
		t.Errorf("ts = %q", got.TS)
	}
	// Finding round-trips as a generic JSON object.
	if got.Finding == nil {
		t.Errorf("finding is nil")
	}
}

// TestRecorder_Tee_AuditMsg pins the audit-event shape.
func TestRecorder_Tee_AuditMsg(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	emit := r.Tee(func(_ tea.Msg) {})
	emit(AuditMsg{Line: "vault unlocked by alice"})

	var got recordEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != "audit" {
		t.Errorf("type = %q, want audit", got.Type)
	}
	if got.Line != "vault unlocked by alice" {
		t.Errorf("line = %q", got.Line)
	}
}

// TestRecorder_Tee_ScanProgressMsg — completed/total
// pointers carry the values across the JSON boundary.
func TestRecorder_Tee_ScanProgressMsg(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	emit := r.Tee(func(_ tea.Msg) {})
	emit(ScanProgressMsg{Completed: 42, Total: 100})

	var got recordEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != "scan_progress" {
		t.Errorf("type = %q, want scan_progress", got.Type)
	}
	if got.Completed == nil || *got.Completed != 42 {
		t.Errorf("completed = %v, want 42", got.Completed)
	}
	if got.Total == nil || *got.Total != 100 {
		t.Errorf("total = %v, want 100", got.Total)
	}
}

// TestRecorder_Tee_FeedClosedMsg — the close event
// carries the mode + the error string (empty when nil).
func TestRecorder_Tee_FeedClosedMsg(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	emit := r.Tee(func(_ tea.Msg) {})

	emit(FeedClosedMsg{Mode: ModeReplay, Err: errors.New("EOF")})

	var got recordEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != "feed_closed" {
		t.Errorf("type = %q, want feed_closed", got.Type)
	}
	if got.Mode != "replay" {
		t.Errorf("mode = %q, want replay", got.Mode)
	}
	if got.Err != "EOF" {
		t.Errorf("err = %q, want EOF", got.Err)
	}

	// Same shape with nil Err — Err field must be empty
	// (omitempty on the struct).
	buf.Reset()
	r2 := newRecorder(nopWriteCloser{&buf})
	emit2 := r2.Tee(func(_ tea.Msg) {})
	emit2(FeedClosedMsg{Mode: ModeInteractive, Err: nil})
	var got2 recordEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got2.Err != "" {
		t.Errorf("nil err: got2.Err = %q, want empty", got2.Err)
	}
}

// TestRecorder_Tee_UnknownMsgPassthrough — messages that
// aren't in the recorded set forward to next without
// writing to disk.
func TestRecorder_Tee_UnknownMsgPassthrough(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	var forwarded []any
	emit := r.Tee(func(m tea.Msg) { forwarded = append(forwarded, m) })

	type customMsg struct{ X int }
	emit(customMsg{X: 7})

	if buf.Len() != 0 {
		t.Errorf("buf written for unknown msg: %s", buf.String())
	}
	if len(forwarded) != 1 {
		t.Errorf("forwarded = %d, want 1", len(forwarded))
	}
}

// TestRecorder_Stats counts successful encodes.
func TestRecorder_Stats(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	emit := r.Tee(func(_ tea.Msg) {})
	emit(FindingMsg{})
	emit(AuditMsg{Line: "x"})
	emit(ScanProgressMsg{Total: 1})
	if r.Stats() != 3 {
		t.Errorf("stats = %d, want 3", r.Stats())
	}
}

// TestRecorder_NDJSONLineFormat — each Encode terminates
// with a newline so consumers can split on \n. We write 3
// events and assert 3 lines.
func TestRecorder_NDJSONLineFormat(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	emit := r.Tee(func(_ tea.Msg) {})
	emit(AuditMsg{Line: "one"})
	emit(AuditMsg{Line: "two"})
	emit(AuditMsg{Line: "three"})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3:\n%s", len(lines), buf.String())
	}
	for i, line := range lines {
		var ev recordEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Errorf("line %d not valid JSON: %v\n%s", i, err, line)
		}
	}
}

// TestRecorder_Close_idempotent — Close is safe to call twice.
func TestRecorder_Close_idempotent(t *testing.T) {
	var buf bytes.Buffer
	r := newRecorder(nopWriteCloser{&buf})
	if err := r.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}
