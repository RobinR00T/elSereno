package scoring

// defaultWeights holds the embedded ADR-006 default weights, loaded
// once at package init. Loading cannot fail at runtime: the YAML is
// embedded and validated by the test suite, so an invalid document is
// a build-time programming error, hence the panic.
var defaultWeights = mustLoadDefaults()

func mustLoadDefaults() Weights {
	w, err := LoadDefaults()
	if err != nil {
		panic("scoring: invalid embedded defaults: " + err.Error())
	}
	return w
}

// ScoreDefault applies the embedded default weights to factors and
// returns the [0,100] score. Single entry point replacing the 29
// hand-copied scoreFor helpers. Behaviour matches them exactly:
// iterate the weights (unknown factors ignored), round, clamp.
func ScoreDefault(factors map[string]int) int {
	var total float64
	for name, weight := range defaultWeights.Values {
		total += weight * float64(factors[name])
	}
	score := int(total + 0.5)
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}
