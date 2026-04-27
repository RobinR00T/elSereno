package repo

import (
	"testing"
	"time"
)

// TestDiffFindingsByTargetProtocol_AllNew — when the old run
// has zero rows, every row from the new run lands in `new`;
// `resolved` and `persisting` are empty.
func TestDiffFindingsByTargetProtocol_AllNew(t *testing.T) {
	newRows := []Finding{
		{ID: "n1", RunID: "rNew", TargetID: "host:502", Protocol: "modbus", Severity: "high", Score: 80, CreatedAt: time.Now()},
	}
	d := diffFindingsByTargetProtocol(nil, newRows)
	if len(d.New) != 1 || len(d.Resolved) != 0 || len(d.Persisting) != 0 {
		t.Errorf("buckets = (new=%d, resolved=%d, persisting=%d); want (1,0,0)", len(d.New), len(d.Resolved), len(d.Persisting))
	}
	if d.New[0].ID != "n1" {
		t.Errorf("New[0].ID = %q, want n1", d.New[0].ID)
	}
}

// TestDiffFindingsByTargetProtocol_AllResolved — new run is
// empty (operator's remediation removed every prior finding).
func TestDiffFindingsByTargetProtocol_AllResolved(t *testing.T) {
	oldRows := []Finding{
		{ID: "o1", RunID: "rOld", TargetID: "host:502", Protocol: "modbus"},
	}
	d := diffFindingsByTargetProtocol(oldRows, nil)
	if len(d.New) != 0 || len(d.Resolved) != 1 || len(d.Persisting) != 0 {
		t.Errorf("buckets = (new=%d, resolved=%d, persisting=%d); want (0,1,0)", len(d.New), len(d.Resolved), len(d.Persisting))
	}
	if d.Resolved[0].ID != "o1" {
		t.Errorf("Resolved[0].ID = %q, want o1", d.Resolved[0].ID)
	}
}

// TestDiffFindingsByTargetProtocol_Persisting — same
// (target_id, protocol) in both runs → persisting; the row
// returned is from the new run (freshest score / factors).
func TestDiffFindingsByTargetProtocol_Persisting(t *testing.T) {
	old := Finding{ID: "o1", RunID: "rOld", TargetID: "host:502", Protocol: "modbus", Score: 50}
	newer := Finding{ID: "n1", RunID: "rNew", TargetID: "host:502", Protocol: "modbus", Score: 90}
	d := diffFindingsByTargetProtocol([]Finding{old}, []Finding{newer})
	if len(d.New) != 0 || len(d.Resolved) != 0 || len(d.Persisting) != 1 {
		t.Errorf("buckets = (new=%d, resolved=%d, persisting=%d); want (0,0,1)", len(d.New), len(d.Resolved), len(d.Persisting))
	}
	if d.Persisting[0].ID != "n1" {
		t.Errorf("Persisting[0].ID = %q; want n1 (new-run row, freshest score)", d.Persisting[0].ID)
	}
	if d.Persisting[0].Score != 90 {
		t.Errorf("Persisting[0].Score = %d; want 90 (new-run row)", d.Persisting[0].Score)
	}
}

// TestDiffFindingsByTargetProtocol_Mixed — exercises all three
// buckets in one diff.
func TestDiffFindingsByTargetProtocol_Mixed(t *testing.T) {
	oldRows := []Finding{
		{ID: "o1", TargetID: "host-a", Protocol: "modbus"}, // resolved
		{ID: "o2", TargetID: "host-b", Protocol: "s7"},     // persists
	}
	newRows := []Finding{
		{ID: "n1", TargetID: "host-b", Protocol: "s7"},  // persists
		{ID: "n2", TargetID: "host-c", Protocol: "fox"}, // new
	}
	d := diffFindingsByTargetProtocol(oldRows, newRows)
	if len(d.New) != 1 || len(d.Resolved) != 1 || len(d.Persisting) != 1 {
		t.Errorf("buckets = (new=%d, resolved=%d, persisting=%d); want (1,1,1)", len(d.New), len(d.Resolved), len(d.Persisting))
	}
}

// TestDiffFindingsByTargetProtocol_DifferentProtocolNoMatch —
// same target, different protocol → both rows are tracked
// independently (one as "resolved", one as "new").
func TestDiffFindingsByTargetProtocol_DifferentProtocolNoMatch(t *testing.T) {
	oldRows := []Finding{
		{ID: "o1", TargetID: "host-a", Protocol: "modbus"},
	}
	newRows := []Finding{
		{ID: "n1", TargetID: "host-a", Protocol: "s7"},
	}
	d := diffFindingsByTargetProtocol(oldRows, newRows)
	if len(d.New) != 1 || len(d.Resolved) != 1 || len(d.Persisting) != 0 {
		t.Errorf("buckets = (new=%d, resolved=%d, persisting=%d); want (1,1,0) — protocol mismatch must NOT fold into persisting", len(d.New), len(d.Resolved), len(d.Persisting))
	}
}

// TestDiffFindingsByTargetProtocol_BothEmpty — defensive: zero
// rows in both runs returns an all-empty diff (not nil).
func TestDiffFindingsByTargetProtocol_BothEmpty(t *testing.T) {
	d := diffFindingsByTargetProtocol(nil, nil)
	if len(d.New) != 0 || len(d.Resolved) != 0 || len(d.Persisting) != 0 {
		t.Errorf("empty/empty diff produced non-empty buckets: %+v", d)
	}
}
