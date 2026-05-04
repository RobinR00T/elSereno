//go:build !mini

package tui

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// recordSchema is the on-disk schema identifier emitted on
// every line of a TUI session record. v1.41+. Operators
// reading these files can dispatch on this string before
// trusting the per-type fields. New event types extend the
// schema in a backwards-compatible way (consumers ignore
// unknown "type" values).
const recordSchema = "elsereno-tui-record/v1"

// recordEvent is the on-disk shape, one per line. The
// `data` shape varies with `type`; consumers select on
// `type` to know which field to read.
//
//	{"schema":"elsereno-tui-record/v1",
//	 "ts":"2026-05-04T19:23:45.123456Z",
//	 "type":"finding",
//	 "finding":{...}}
//
//	{"schema":"elsereno-tui-record/v1",
//	 "ts":"...",
//	 "type":"audit",
//	 "line":"vault unlocked by alice"}
//
//	{"schema":"elsereno-tui-record/v1",
//	 "ts":"...",
//	 "type":"scan_progress",
//	 "completed":42, "total":100}
//
//	{"schema":"elsereno-tui-record/v1",
//	 "ts":"...",
//	 "type":"feed_closed",
//	 "mode":"interactive", "err":""}
type recordEvent struct {
	Schema string `json:"schema"`
	TS     string `json:"ts"`
	Type   string `json:"type"`

	// type=finding
	Finding any `json:"finding,omitempty"`

	// type=audit
	Line string `json:"line,omitempty"`

	// type=scan_progress
	Completed *int64 `json:"completed,omitempty"`
	Total     *int64 `json:"total,omitempty"`

	// type=feed_closed
	Mode string `json:"mode,omitempty"`
	Err  string `json:"err,omitempty"`
}

// recorder tees tea.Msg events to an NDJSON file. Owns
// the file handle for the recorder's lifetime; Close
// finalises it. Methods are safe for concurrent use — the
// feed goroutine is the only producer in production but
// tests + future multi-feed compositions might overlap.
type recorder struct {
	mu      sync.Mutex
	w       io.WriteCloser
	enc     *json.Encoder
	now     func() time.Time
	written int
}

// newRecorder wraps w as the JSON sink. The caller owns
// the io.WriteCloser's filesystem lifetime; recorder only
// closes it via the recorder's own Close. Each Encode
// appends a newline, so we write canonical NDJSON.
func newRecorder(w io.WriteCloser) *recorder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &recorder{
		w:   w,
		enc: enc,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Tee returns an emit-shim that records the message + then
// forwards to next. Used by runner.Run when --record is set.
//
// Records every message type the recordEvent shape covers;
// unknown types pass through to next without being persisted
// (the consumer can't replay what it doesn't understand
// anyway). A schema-bump cycle would extend this.
func (r *recorder) Tee(next func(tea.Msg)) func(tea.Msg) {
	return func(msg tea.Msg) {
		r.record(msg)
		next(msg)
	}
}

// record serialises one message and writes a JSON line.
// Errors are silenced — recording is best-effort, the
// operator-supplied file might fill the disk mid-session
// and the TUI shouldn't die for that. The Stats() method
// surfaces the line count so the caller can sanity-check.
func (r *recorder) record(msg tea.Msg) {
	ev := r.eventFor(msg)
	if ev.Type == "" {
		return // unrecorded message kind
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.enc.Encode(ev); err == nil {
		r.written++
	}
}

// eventFor maps a tea.Msg to the on-disk shape. Returns a
// zero-Type event for unknown / unrecorded messages so the
// caller can short-circuit the disk write.
func (r *recorder) eventFor(msg tea.Msg) recordEvent {
	ts := r.now().Format(time.RFC3339Nano)
	switch m := msg.(type) {
	case FindingMsg:
		return recordEvent{
			Schema:  recordSchema,
			TS:      ts,
			Type:    "finding",
			Finding: m.Finding,
		}
	case AuditMsg:
		return recordEvent{
			Schema: recordSchema,
			TS:     ts,
			Type:   "audit",
			Line:   m.Line,
		}
	case ScanProgressMsg:
		c, t := m.Completed, m.Total
		return recordEvent{
			Schema:    recordSchema,
			TS:        ts,
			Type:      "scan_progress",
			Completed: &c,
			Total:     &t,
		}
	case FeedClosedMsg:
		errStr := ""
		if m.Err != nil {
			errStr = m.Err.Error()
		}
		return recordEvent{
			Schema: recordSchema,
			TS:     ts,
			Type:   "feed_closed",
			Mode:   string(m.Mode),
			Err:    errStr,
		}
	}
	return recordEvent{}
}

// Close finalises the underlying writer.
func (r *recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.w == nil {
		return nil
	}
	err := r.w.Close()
	r.w = nil
	return err
}

// Stats returns the number of events successfully recorded.
// Used by tests and the operator's "wrote N events to FILE"
// summary at end-of-session.
func (r *recorder) Stats() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.written
}

// _ ensure encoding/json import doesn't drift.
var _ = fmt.Errorf
