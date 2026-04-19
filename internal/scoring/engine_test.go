package scoring_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scoring"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	w, err := scoring.LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults: %v", err)
	}
	for _, name := range scoring.DefaultFactors {
		if _, ok := w.Values[name]; !ok {
			t.Fatalf("defaults missing %q", name)
		}
	}
}

func TestValidateSum(t *testing.T) {
	t.Parallel()
	// 0.3 + 0.3 + 0.4 = 1.0
	w := map[string]float64{
		"protocol_risk": 0.3, "exposure": 0.3, "auth_state": 0.4,
		"capability": 0, "impact_class": 0, "cve_exposure": 0,
	}
	if err := scoring.Validate(w); err != nil {
		t.Fatalf("valid weights rejected: %v", err)
	}

	w["auth_state"] = 0.5 // sum = 1.1
	if err := scoring.Validate(w); !errors.Is(err, scoring.ErrInvalidWeights) {
		t.Fatalf("got %v, want ErrInvalidWeights", err)
	}

	w["auth_state"] = -0.1 // negative factor
	if err := scoring.Validate(w); !errors.Is(err, scoring.ErrInvalidWeights) {
		t.Fatalf("got %v, want ErrInvalidWeights", err)
	}
}

func TestValidateMissingFactor(t *testing.T) {
	t.Parallel()
	w := map[string]float64{
		"protocol_risk": 1.0,
		// missing the other five
	}
	if err := scoring.Validate(w); !errors.Is(err, scoring.ErrInvalidWeights) {
		t.Fatalf("got %v, want ErrInvalidWeights", err)
	}
}

func TestScoreHappyPath(t *testing.T) {
	t.Parallel()
	w, err := scoring.LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults: %v", err)
	}
	// All factors at 50 -> score = 50 -> medium.
	factors := make(map[string]int, len(scoring.DefaultFactors))
	for _, name := range scoring.DefaultFactors {
		factors[name] = 50
	}
	score, sev, err := scoring.Score(w, factors)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score != 50 {
		t.Fatalf("score=%d want 50", score)
	}
	if sev != core.SeverityMedium {
		t.Fatalf("sev=%s want medium", sev)
	}

	// All at 100 -> 100 -> critical.
	for name := range factors {
		factors[name] = 100
	}
	score, sev, err = scoring.Score(w, factors)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if score != 100 || sev != core.SeverityCritical {
		t.Fatalf("score=%d sev=%s", score, sev)
	}
}

func TestScoreRejectsUnknownFactor(t *testing.T) {
	t.Parallel()
	w, _ := scoring.LoadDefaults()
	factors := map[string]int{"protocol_risk": 50, "made_up_factor": 90}
	_, _, err := scoring.Score(w, factors)
	if !errors.Is(err, scoring.ErrUnknownFactor) {
		t.Fatalf("got %v, want ErrUnknownFactor", err)
	}
}

func TestScoreRejectsOutOfRange(t *testing.T) {
	t.Parallel()
	w, _ := scoring.LoadDefaults()
	factors := map[string]int{"protocol_risk": 150}
	_, _, err := scoring.Score(w, factors)
	if !errors.Is(err, scoring.ErrFactorOutOfRange) {
		t.Fatalf("got %v, want ErrFactorOutOfRange", err)
	}
}

func TestFactorsOrdered(t *testing.T) {
	t.Parallel()
	w, _ := scoring.LoadDefaults()
	got := w.Factors()
	if len(got) != len(scoring.DefaultFactors) {
		t.Fatalf("got %d factors, want %d", len(got), len(scoring.DefaultFactors))
	}
	for i, name := range scoring.DefaultFactors {
		if got[i] != name {
			t.Fatalf("Factors()[%d] = %q, want %q", i, got[i], name)
		}
	}
}
