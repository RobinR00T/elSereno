package csv_test

import (
	"bytes"
	encodingcsv "encoding/csv"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	esecsv "local/elsereno/internal/outputs/csv"
)

func TestWriteFindingEmitsCSV(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	w := esecsv.NewWriter(&buf)
	f := core.Finding{
		ID:        core.UUID("ffffffff-ffff-4fff-8fff-ffffffffffff"),
		RunID:     core.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
		TargetID:  core.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
		Protocol:  "modbus",
		Severity:  core.SeverityHigh,
		Score:     65,
		CreatedAt: time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC),
	}
	if err := w.WriteFinding(f, "10.0.0.1", 502); err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r := encodingcsv.NewReader(strings.NewReader(buf.String()))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (header + 1)", len(rows))
	}
	if rows[0][0] != "schema" {
		t.Fatalf("header[0] = %q, want schema", rows[0][0])
	}
	if rows[1][0] != esecsv.Contract {
		t.Fatalf("row[0] = %q, want %q", rows[1][0], esecsv.Contract)
	}
	if rows[1][4] != "502" {
		t.Fatalf("port column = %q, want 502", rows[1][4])
	}
}
