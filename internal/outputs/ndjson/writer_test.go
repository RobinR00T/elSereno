package ndjson_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/ndjson"
)

func TestWriteFindingEmitsNDJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := ndjson.NewWriter(&buf)
	f := core.Finding{
		ID:        core.UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
		RunID:     core.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		TargetID:  core.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		Protocol:  "modbus",
		Severity:  core.SeverityHigh,
		Score:     65,
		CreatedAt: time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC),
		Factors:   map[string]int{"protocol_risk": 80},
	}
	if err := w.WriteFinding(f, "10.0.0.1"); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	out := buf.Bytes()
	if len(out) == 0 || out[len(out)-1] != '\n' {
		t.Fatalf("ndjson must end with newline; got %q", out)
	}
	var r ndjson.Record
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Schema != ndjson.Contract {
		t.Fatalf("schema = %q, want %q", r.Schema, ndjson.Contract)
	}
	if r.Score != 65 || r.Severity != "high" || r.Address != "10.0.0.1" {
		t.Fatalf("unexpected record: %+v", r)
	}
}
