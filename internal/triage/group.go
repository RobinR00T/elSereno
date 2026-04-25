package triage

import (
	"sort"

	"local/elsereno/internal/core"
)

// Bucket labels.
const (
	BucketQuickWin  = "quick_win"
	BucketStrategic = "strategic"
	BucketUtility   = "utility"
	BucketRoutine   = "routine"
)

// Group places a finding into a triage bucket.
//
//   - quick_win:  severity in {critical, high} AND no auth configured
//     on the target (auth_state == 0) — remediated fast
//     because the fix is usually "turn on auth".
//   - strategic:  severity == critical AND impact_class > 60
//     — matters for long-horizon remediation plans.
//   - utility:    severity in {info, low} AND the finding surfaces
//     reconnaissance / inventory value (banner data, version
//     leaks, vendor identification) but isn't directly
//     exploitable. v1.13 chunk 6 split this out of routine
//     so operators can see what's "useful intel"
//     vs. "background noise". Heuristic: severity ≤ low
//     AND (banner-style plugin OR no impact factor present).
//   - routine:    everything else.
//
// Callers that disagree with the policy can override via a YAML
// override file in F1 chunk 3; this implementation is deliberately
// opinionated.
func Group(f core.Finding) string {
	authState, okA := f.Factors["auth_state"]
	impact, okI := f.Factors["impact_class"]

	if f.Severity == core.SeverityCritical || f.Severity == core.SeverityHigh {
		if okA && authState <= 10 {
			return BucketQuickWin
		}
	}
	if f.Severity == core.SeverityCritical && okI && impact >= 60 {
		return BucketStrategic
	}
	if isUtilityFinding(f, okI, impact) {
		return BucketUtility
	}
	return BucketRoutine
}

// isUtilityFinding implements the v1.13 chunk-6 utility heuristic.
// A finding lands in "utility" when its severity is ≤ low AND
// either:
//
//   - the protocol is the generic banner / dictionary plugin
//     (whose findings are inventory data, not vulnerabilities),
//     OR
//   - the impact_class factor is absent or near-zero (informational
//     signal, no operational lever).
//
// Severity > low always falls through (those are real findings
// regardless of impact). The result is intentionally narrow —
// "utility" should be a small, useful bucket that surfaces
// recon-grade signals an operator wants to see, not a dumping
// ground for everything routine.
func isUtilityFinding(f core.Finding, okImpact bool, impact int) bool {
	if f.Severity != core.SeverityInfo && f.Severity != core.SeverityLow {
		return false
	}
	if f.Protocol == "banner" || f.Protocol == "atmodem" {
		return true
	}
	if !okImpact || impact < 20 {
		return true
	}
	return false
}

// Summary aggregates findings into per-bucket counts with a stable
// ordering (quick_win, strategic, utility, routine).
type Summary struct {
	QuickWin  []core.Finding
	Strategic []core.Finding
	Utility   []core.Finding
	Routine   []core.Finding
}

// BucketFindings returns a Summary with findings split by bucket.
// Within each bucket, findings are sorted by Score descending to put
// the worst at the top.
func BucketFindings(findings []core.Finding) Summary {
	var s Summary
	for _, f := range findings {
		switch Group(f) {
		case BucketQuickWin:
			s.QuickWin = append(s.QuickWin, f)
		case BucketStrategic:
			s.Strategic = append(s.Strategic, f)
		case BucketUtility:
			s.Utility = append(s.Utility, f)
		default:
			s.Routine = append(s.Routine, f)
		}
	}
	for _, bucket := range [][]core.Finding{s.QuickWin, s.Strategic, s.Utility, s.Routine} {
		sort.SliceStable(bucket, func(i, j int) bool { return bucket[i].Score > bucket[j].Score })
	}
	return s
}
