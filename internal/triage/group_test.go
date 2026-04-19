package triage_test

import (
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/triage"
)

func TestGroupQuickWin(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Severity: core.SeverityCritical,
		Score:    90,
		Factors:  map[string]int{"auth_state": 0, "impact_class": 30},
	}
	if got := triage.Group(f); got != triage.BucketQuickWin {
		t.Fatalf("Group = %q, want quick_win", got)
	}
}

func TestGroupStrategic(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Severity: core.SeverityCritical,
		Score:    85,
		Factors:  map[string]int{"auth_state": 90, "impact_class": 80},
	}
	if got := triage.Group(f); got != triage.BucketStrategic {
		t.Fatalf("Group = %q, want strategic", got)
	}
}

func TestGroupRoutine(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Severity: core.SeverityMedium,
		Score:    45,
		Factors:  map[string]int{"auth_state": 50, "impact_class": 30},
	}
	if got := triage.Group(f); got != triage.BucketRoutine {
		t.Fatalf("Group = %q, want routine", got)
	}
}

func TestBucketFindingsSorted(t *testing.T) {
	t.Parallel()
	findings := []core.Finding{
		{Severity: core.SeverityCritical, Score: 85, Factors: map[string]int{"auth_state": 0}},
		{Severity: core.SeverityHigh, Score: 70, Factors: map[string]int{"auth_state": 5}},
		{Severity: core.SeverityCritical, Score: 95, Factors: map[string]int{"auth_state": 0}},
		{Severity: core.SeverityMedium, Score: 50, Factors: map[string]int{"auth_state": 50}},
	}
	s := triage.BucketFindings(findings)
	if len(s.QuickWin) != 3 {
		t.Fatalf("QuickWin len = %d, want 3", len(s.QuickWin))
	}
	if s.QuickWin[0].Score != 95 {
		t.Fatalf("QuickWin[0].Score = %d, want 95", s.QuickWin[0].Score)
	}
	if len(s.Routine) != 1 {
		t.Fatalf("Routine len = %d, want 1", len(s.Routine))
	}
}
