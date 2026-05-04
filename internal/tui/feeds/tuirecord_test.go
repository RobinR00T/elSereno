//go:build !mini

package feeds

import (
	"context"
	"strings"
	"testing"

	"local/elsereno/internal/tui"
)

// TestParseTUIRecord_FindingType — a finding event from the
// v1.41 schema produces a FindingMsg with the Score / Protocol
// preserved.
func TestParseTUIRecord_FindingType(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","ts":"2026-05-04T12:00:00Z","type":"finding","finding":{"Score":91,"Protocol":"modbus","Severity":"high"}}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if len(d.msgs) != 1 {
		t.Fatalf("emitted %d, want 1", len(d.msgs))
	}
	fm, ok := d.msgs[0].(tui.FindingMsg)
	if !ok {
		t.Fatalf("[0] = %T, want FindingMsg", d.msgs[0])
	}
	if fm.Finding.Score != 91 {
		t.Errorf("score = %d, want 91", fm.Finding.Score)
	}
	if fm.Finding.Protocol != "modbus" {
		t.Errorf("protocol = %q, want modbus", fm.Finding.Protocol)
	}
}

// TestParseTUIRecord_AuditType — audit lines round-trip
// through the schema.
func TestParseTUIRecord_AuditType(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","ts":"2026-05-04T12:00:00Z","type":"audit","line":"vault unlocked"}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	am, ok := d.msgs[0].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[0] = %T, want AuditMsg", d.msgs[0])
	}
	if am.Line != "vault unlocked" {
		t.Errorf("line = %q", am.Line)
	}
}

// TestParseTUIRecord_ScanProgressType — completed/total
// pointers round-trip through the schema.
func TestParseTUIRecord_ScanProgressType(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","ts":"2026-05-04T12:00:00Z","type":"scan_progress","completed":42,"total":100}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	pm, ok := d.msgs[0].(tui.ScanProgressMsg)
	if !ok {
		t.Fatalf("[0] = %T, want ScanProgressMsg", d.msgs[0])
	}
	if pm.Completed != 42 {
		t.Errorf("completed = %d, want 42", pm.Completed)
	}
	if pm.Total != 100 {
		t.Errorf("total = %d, want 100", pm.Total)
	}
}

// TestParseTUIRecord_ScanProgressNilFields — when completed
// or total are nil in the JSON, the resulting Msg has zero
// values (no panic, no surprise).
func TestParseTUIRecord_ScanProgressNilFields(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","type":"scan_progress"}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	pm, ok := d.msgs[0].(tui.ScanProgressMsg)
	if !ok {
		t.Fatalf("[0] = %T, want ScanProgressMsg", d.msgs[0])
	}
	if pm.Completed != 0 || pm.Total != 0 {
		t.Errorf("got (%d, %d), want (0, 0)", pm.Completed, pm.Total)
	}
}

// TestParseTUIRecord_FeedClosedType — mode + err round-trip.
func TestParseTUIRecord_FeedClosedType(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","type":"feed_closed","mode":"replay","err":"EOF"}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	cm, ok := d.msgs[0].(tui.FeedClosedMsg)
	if !ok {
		t.Fatalf("[0] = %T, want FeedClosedMsg", d.msgs[0])
	}
	if string(cm.Mode) != "replay" {
		t.Errorf("mode = %q", cm.Mode)
	}
	if cm.Err == nil || cm.Err.Error() != "EOF" {
		t.Errorf("err = %v", cm.Err)
	}
}

// TestParseTUIRecord_FeedClosedNilErr — empty err string
// yields a nil error in the resulting Msg.
func TestParseTUIRecord_FeedClosedNilErr(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","type":"feed_closed","mode":"interactive"}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	cm, ok := d.msgs[0].(tui.FeedClosedMsg)
	if !ok {
		t.Fatalf("[0] = %T, want FeedClosedMsg", d.msgs[0])
	}
	if cm.Err != nil {
		t.Errorf("err = %v, want nil", cm.Err)
	}
}

// TestParseTUIRecord_UnknownType — a forward-compat schema
// bump that adds a new event type renders as an AuditMsg
// with the "unknown type" hint.
func TestParseTUIRecord_UnknownType(t *testing.T) {
	line := `{"schema":"elsereno-tui-record/v1","type":"future_event","data":42}`
	src := strings.NewReader(line + "\n")
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	am, ok := d.msgs[0].(tui.AuditMsg)
	if !ok {
		t.Fatalf("[0] = %T, want AuditMsg", d.msgs[0])
	}
	if !strings.Contains(am.Line, "unknown type") {
		t.Errorf("line = %q, want 'unknown type'", am.Line)
	}
}

// TestParseRecord_MultiSchemaInOneFile — a file mixing
// ndjson:v1 + elsereno-tui-record/v1 lines streams through
// without skipping either.
func TestParseRecord_MultiSchemaInOneFile(t *testing.T) {
	src := strings.NewReader(strings.Join([]string{
		`{"schema":"ndjson:v1","run_id":"r","target_id":"t","address":"10.0.0.1","port":502,"protocol":"modbus","severity":"high","score":85,"factors":{},"created_at":"2026-04-29T12:00:00Z"}`,
		`{"schema":"elsereno-tui-record/v1","type":"audit","line":"hello"}`,
		`{"schema":"elsereno-tui-record/v1","type":"finding","finding":{"Score":91,"Protocol":"s7"}}`,
	}, "\n"))
	d := &drain{}
	if err := (Replay{Path: "test"}).stream(context.Background(), src, d.emit()); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if len(d.msgs) != 3 {
		t.Fatalf("emitted %d, want 3", len(d.msgs))
	}
	if _, ok := d.msgs[0].(tui.FindingMsg); !ok {
		t.Errorf("[0] not FindingMsg (legacy schema)")
	}
	if _, ok := d.msgs[1].(tui.AuditMsg); !ok {
		t.Errorf("[1] not AuditMsg")
	}
	fm, ok := d.msgs[2].(tui.FindingMsg)
	if !ok {
		t.Fatalf("[2] not FindingMsg (new schema)")
	}
	if fm.Finding.Score != 91 || fm.Finding.Protocol != "s7" {
		t.Errorf("[2] finding = %+v", fm.Finding)
	}
}
