package scoring

import "testing"

// manualScoreFor reproduces the exact computation of the 29
// hand-copied scoreFor helpers that ScoreDefault replaces: iterate the
// ADR-006 weights, multiply by each factor sub-score, round with
// int(total+0.5), then clamp to [0,100].
func manualScoreFor(factors map[string]int) int {
	weights := map[string]float64{
		"protocol_risk": 0.25,
		"exposure":      0.20,
		"auth_state":    0.20,
		"capability":    0.15,
		"impact_class":  0.10,
		"cve_exposure":  0.10,
	}
	var total float64
	for k, w := range weights {
		total += float64(factors[k]) * w
	}
	n := int(total + 0.5)
	if n < 0 {
		n = 0
	}
	if n > 100 {
		n = 100
	}
	return n
}

func TestScoreDefaultMatchesManual(t *testing.T) {
	cases := []map[string]int{
		{
			"protocol_risk": 75, "exposure": 80, "auth_state": 95,
			"capability": 30, "impact_class": 60, "cve_exposure": 6,
		},
		{
			"protocol_risk": 10, "exposure": 40, "auth_state": 80,
			"capability": 0, "impact_class": 0, "cve_exposure": 0,
		},
		{
			"protocol_risk": 100, "exposure": 100, "auth_state": 100,
			"capability": 100, "impact_class": 100, "cve_exposure": 100,
		},
		{}, // all-zero / missing factors
		{
			// Unknown factors must be ignored, exactly as the old helper did.
			"protocol_risk": 50, "exposure": 50, "auth_state": 50,
			"capability": 50, "impact_class": 50, "cve_exposure": 50,
			"not_a_factor": 999,
		},
	}
	for i, factors := range cases {
		got := ScoreDefault(factors)
		want := manualScoreFor(factors)
		if got != want {
			t.Errorf("case %d: ScoreDefault=%d, manual scoreFor=%d, factors=%v", i, got, want, factors)
		}
	}
}

func TestScoreDefaultKnownValue(t *testing.T) {
	// 0.25*75 + 0.20*80 + 0.20*95 + 0.15*30 + 0.10*60 + 0.10*6
	// = 18.75 + 16 + 19 + 4.5 + 6 + 0.6 = 64.85 -> int(65.35) = 65
	factors := map[string]int{
		"protocol_risk": 75, "exposure": 80, "auth_state": 95,
		"capability": 30, "impact_class": 60, "cve_exposure": 6,
	}
	if got := ScoreDefault(factors); got != 65 {
		t.Fatalf("ScoreDefault=%d, want 65", got)
	}
}

func TestScoreDefaultClampsHigh(t *testing.T) {
	factors := map[string]int{
		"protocol_risk": 100, "exposure": 100, "auth_state": 100,
		"capability": 100, "impact_class": 100, "cve_exposure": 100,
	}
	if got := ScoreDefault(factors); got != 100 {
		t.Fatalf("ScoreDefault=%d, want 100", got)
	}
}
