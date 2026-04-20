package scoring_test

import (
	"testing"

	"local/elsereno/internal/scoring"
)

// BenchmarkScore measures the hot path every finding goes through.
// The workload fills the full 6-factor set defined by ADR-006 so
// the benchmark reflects production cost.
func BenchmarkScore(b *testing.B) {
	w, err := scoring.LoadDefaults()
	if err != nil {
		b.Fatal(err)
	}
	factors := map[string]int{
		"protocol_risk": 85,
		"exposure":      80,
		"auth_state":    90,
		"capability":    60,
		"impact_class":  70,
		"cve_exposure":  0,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := scoring.Score(w, factors)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadDefaults measures the weights + YAML load path that
// runs once per `serve` startup. Kept as a guardrail against a
// dependency that might balloon the parse time.
func BenchmarkLoadDefaults(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := scoring.LoadDefaults()
		if err != nil {
			b.Fatal(err)
		}
	}
}
