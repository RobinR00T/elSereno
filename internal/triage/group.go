package triage

import (
	"sort"

	"local/elsereno/internal/core"
)

// Bucket labels.
const (
	BucketQuickWin  = "quick_win"
	BucketStrategic = "strategic"
	BucketRoutine   = "routine"
)

// Group places a finding into a triage bucket.
//
//   - quick_win:  severity in {critical, high} AND no auth configured
//     on the target (auth_state == 0) — remediated fast
//     because the fix is usually "turn on auth".
//   - strategic:  severity == critical AND impact_class > 60
//     — matters for long-horizon remediation plans.
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
	return BucketRoutine
}

// Summary aggregates findings into per-bucket counts with a stable
// ordering (quick_win, strategic, routine).
type Summary struct {
	QuickWin  []core.Finding
	Strategic []core.Finding
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
		default:
			s.Routine = append(s.Routine, f)
		}
	}
	for _, bucket := range [][]core.Finding{s.QuickWin, s.Strategic, s.Routine} {
		sort.SliceStable(bucket, func(i, j int) bool { return bucket[i].Score > bucket[j].Score })
	}
	return s
}
