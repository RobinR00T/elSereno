package repo_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/core"
	"local/elsereno/internal/repo"
)

// writerFake records every statement and answers the target upsert.
type writerFake struct {
	stmts   []string
	args    [][]any
	execErr error
}

func (f *writerFake) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not used")
}

func (f *writerFake) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.stmts = append(f.stmts, sql)
	f.args = append(f.args, args)
	return targetRow{}
}

func (f *writerFake) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.stmts = append(f.stmts, sql)
	f.args = append(f.args, args)
	return pgconn.CommandTag{}, f.execErr
}

type targetRow struct{}

func (targetRow) Scan(dest ...any) error {
	id, ok := dest[0].(*string)
	if !ok {
		return fmt.Errorf("targetRow: scan into %T", dest[0])
	}
	*id = "11111111-1111-4111-8111-111111111111"
	return nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestRunWriter_RecordsRunAndFinding: a run and its finding land in the
// tables the dashboard reads, with the target upserted and a hash
// derived when the probe gave none (PITF-094).
func TestRunWriter_RecordsRunAndFinding(t *testing.T) {
	q := &writerFake{}
	w := repo.NewRunWriter(q)
	ctx := context.Background()

	runID, err := w.StartRun(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !uuidRE.MatchString(runID) {
		t.Fatalf("run id %q is not a v4 UUID", runID)
	}
	f := core.Finding{Protocol: "modbus", Severity: core.SeverityHigh, Score: 72, Factors: map[string]int{"exposure": 80}}
	got, err := w.RecordFinding(ctx, runID, f, netip.MustParseAddr("192.0.2.7"), 502)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.RunID) != runID || string(got.TargetID) != "11111111-1111-4111-8111-111111111111" || !uuidRE.MatchString(string(got.ID)) {
		t.Fatalf("stored finding ids = %+v", got)
	}
	if len(got.FindingHash) != 32 || got.CreatedAt.IsZero() {
		t.Fatalf("hash %x / created_at %v not filled", got.FindingHash, got.CreatedAt)
	}
	if err := w.FinishRun(ctx, runID, "completed"); err != nil {
		t.Fatal(err)
	}

	want := []string{"INSERT INTO runs", "INSERT INTO targets", "INSERT INTO findings", "UPDATE runs"}
	if len(q.stmts) != len(want) {
		t.Fatalf("%d statements, want %d: %q", len(q.stmts), len(want), q.stmts)
	}
	for i, prefix := range want {
		if !strings.Contains(q.stmts[i], prefix) {
			t.Errorf("statement %d = %q, want %s", i, q.stmts[i], prefix)
		}
	}
	if q.args[1][1] != "192.0.2.7" || q.args[1][2] != 502 {
		t.Errorf("target upsert args = %v", q.args[1])
	}
	var factors map[string]int
	raw, ok := q.args[2][8].([]byte)
	if !ok {
		t.Fatalf("factors arg is %T, want []byte", q.args[2][8])
	}
	if err := json.Unmarshal(raw, &factors); err != nil || factors["exposure"] != 80 {
		t.Errorf("factors JSON = %s (%v)", q.args[2][8], err)
	}
	if q.args[3][1] != "completed" {
		t.Errorf("finish status = %v", q.args[3][1])
	}
}

// TestRunWriter_ReportsWriteFailures: a failed insert is an error, so
// the runner stops probing instead of losing findings.
func TestRunWriter_ReportsWriteFailures(t *testing.T) {
	q := &writerFake{execErr: errors.New("disk full")}
	w := repo.NewRunWriter(q)
	if _, err := w.StartRun(context.Background(), "alice"); err == nil {
		t.Fatal("StartRun hid the database error")
	}
	if _, err := w.RecordFinding(context.Background(), "r", core.Finding{Protocol: "s7"}, netip.MustParseAddr("192.0.2.8"), 102); err == nil {
		t.Fatal("RecordFinding hid the database error")
	}
}

// TestRunWriter_DropsIPv6Zone: INET has no zone, so fe80::1%en0 is
// stored as fe80::1 (and a v4-mapped address as plain v4).
func TestRunWriter_DropsIPv6Zone(t *testing.T) {
	for in, want := range map[string]string{"fe80::1%en0": "fe80::1", "::ffff:192.0.2.7": "192.0.2.7"} {
		q := &writerFake{}
		if _, err := repo.NewRunWriter(q).RecordFinding(context.Background(), "11111111-1111-4111-8111-111111111111",
			core.Finding{Protocol: "modbus"}, netip.MustParseAddr(in), 502); err != nil {
			t.Fatal(err)
		}
		if q.args[0][1] != want {
			t.Errorf("%s stored as %v, want %s", in, q.args[0][1], want)
		}
	}
}
