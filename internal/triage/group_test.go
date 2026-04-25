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
		// Medium / impact missing → not utility (severity > low),
		// not quick_win (auth_state > 10), not strategic (severity
		// not critical) → routine.
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

// TestGroupUtility_BannerInfoFinding — generic banner-plugin
// finding at severity-info lands in utility (recon data, not a
// vulnerability).
func TestGroupUtility_BannerInfoFinding(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Protocol: "banner",
		Severity: core.SeverityInfo,
		Score:    15,
		Factors:  map[string]int{},
	}
	if got := triage.Group(f); got != triage.BucketUtility {
		t.Fatalf("Group = %q, want utility", got)
	}
}

// TestGroupUtility_ATModemBannerLands — atmodem banners are
// inventory data (modem fingerprint), so they land in utility
// at low severity.
func TestGroupUtility_ATModemBannerLands(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Protocol: "atmodem",
		Severity: core.SeverityLow,
		Score:    25,
		Factors:  map[string]int{"impact_class": 30},
	}
	if got := triage.Group(f); got != triage.BucketUtility {
		t.Fatalf("Group = %q, want utility", got)
	}
}

// TestGroupUtility_LowSeverityNoImpactLandsHere — a low-severity
// finding with no impact_class factor (information leak with
// no direct exploit) lands in utility.
func TestGroupUtility_LowSeverityNoImpactLandsHere(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Protocol: "modbus",
		Severity: core.SeverityLow,
		Score:    25,
		Factors:  map[string]int{},
	}
	if got := triage.Group(f); got != triage.BucketUtility {
		t.Fatalf("Group = %q, want utility", got)
	}
}

// TestGroupUtility_MediumSeverityNeverUtility — medium and above
// never land in utility, even with no impact factor.
func TestGroupUtility_MediumSeverityNeverUtility(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Protocol: "banner",
		Severity: core.SeverityMedium,
		Score:    50,
		Factors:  map[string]int{},
	}
	if got := triage.Group(f); got == triage.BucketUtility {
		t.Fatalf("medium-severity finding should never be utility, got %q", got)
	}
}

// TestGroupUtility_LowWithImpactNotUtility — a low-severity
// finding with a non-trivial impact_class is operational, not
// inventory; lands in routine.
func TestGroupUtility_LowWithImpactNotUtility(t *testing.T) {
	t.Parallel()
	f := core.Finding{
		Protocol: "modbus",
		Severity: core.SeverityLow,
		Score:    35,
		Factors:  map[string]int{"impact_class": 45},
	}
	if got := triage.Group(f); got != triage.BucketRoutine {
		t.Fatalf("Group = %q, want routine (low + impact ≥ 20)", got)
	}
}

// TestBucketFindingsSeparatesUtility — full Summary check: the
// utility bucket carries banner-info findings while routine
// carries everything else low-severity.
func TestBucketFindingsSeparatesUtility(t *testing.T) {
	t.Parallel()
	findings := []core.Finding{
		{Protocol: "banner", Severity: core.SeverityInfo, Score: 5, Factors: map[string]int{}},
		{Protocol: "modbus", Severity: core.SeverityLow, Score: 30, Factors: map[string]int{"impact_class": 50}},
		{Protocol: "atmodem", Severity: core.SeverityLow, Score: 25, Factors: map[string]int{"impact_class": 30}},
		{Protocol: "modbus", Severity: core.SeverityCritical, Score: 95, Factors: map[string]int{"auth_state": 0}},
	}
	s := triage.BucketFindings(findings)
	if len(s.Utility) != 2 {
		t.Errorf("Utility len=%d, want 2 (banner + atmodem)", len(s.Utility))
	}
	if len(s.Routine) != 1 {
		t.Errorf("Routine len=%d, want 1 (modbus low + impact)", len(s.Routine))
	}
	if len(s.QuickWin) != 1 {
		t.Errorf("QuickWin len=%d, want 1 (modbus critical)", len(s.QuickWin))
	}
	// Utility entries sorted by Score desc.
	if s.Utility[0].Score < s.Utility[1].Score {
		t.Errorf("Utility not sorted by Score desc: %+v", s.Utility)
	}
}
