package scoring

import (
	"embed"
	"errors"
	"fmt"
	"math"
	"sort"

	"go.yaml.in/yaml/v3"

	"local/elsereno/internal/core"
)

// ErrInvalidWeights is returned when factor weights do not sum to 1.0
// (within 1e-9) or a factor is negative.
var ErrInvalidWeights = errors.New("scoring: invalid weights")

// ErrUnknownFactor is returned when sub-scores reference a factor name
// that is not in the loaded weights map.
var ErrUnknownFactor = errors.New("scoring: unknown factor")

// ErrFactorOutOfRange is returned when a sub-score is outside [0, 100].
var ErrFactorOutOfRange = errors.New("scoring: factor sub-score out of [0,100]")

// DefaultFactors names the six ADR-006 factors in canonical order.
var DefaultFactors = []string{
	"protocol_risk",
	"exposure",
	"auth_state",
	"capability",
	"impact_class",
	"cve_exposure",
}

//go:embed defaults/*.yaml
var defaultsFS embed.FS

// Weights maps factor name -> weight in [0, 1]. Weights must sum to
// 1.0 within 1e-9.
type Weights struct {
	Values map[string]float64
}

// WeightsYAML is the on-disk shape used by defaults/weights.yaml.
type WeightsYAML struct {
	Version string             `yaml:"version"`
	Weights map[string]float64 `yaml:"weights"`
}

// LoadDefaults parses the embedded defaults/weights.yaml.
func LoadDefaults() (Weights, error) {
	b, err := defaultsFS.ReadFile("defaults/weights.yaml")
	if err != nil {
		return Weights{}, fmt.Errorf("scoring: read embedded defaults: %w", err)
	}
	return ParseWeights(b)
}

// ParseWeights decodes a YAML document and validates the resulting map.
func ParseWeights(raw []byte) (Weights, error) {
	var doc WeightsYAML
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return Weights{}, fmt.Errorf("scoring: parse weights: %w", err)
	}
	if err := Validate(doc.Weights); err != nil {
		return Weights{}, err
	}
	return Weights{Values: doc.Weights}, nil
}

// Validate enforces that weights sum to 1.0 (±1e-9), each weight is in
// [0, 1], and every required factor is present.
func Validate(w map[string]float64) error {
	if len(w) == 0 {
		return fmt.Errorf("%w: empty weights map", ErrInvalidWeights)
	}

	// Required factors must be present; extras are allowed to support
	// per-deployment overrides.
	for _, name := range DefaultFactors {
		if _, ok := w[name]; !ok {
			return fmt.Errorf("%w: missing factor %q", ErrInvalidWeights, name)
		}
	}

	var sum float64
	for name, v := range w {
		if v < 0 || v > 1 {
			return fmt.Errorf("%w: %s = %v not in [0, 1]", ErrInvalidWeights, name, v)
		}
		sum += v
	}
	const eps = 1e-9
	if math.Abs(sum-1.0) > eps {
		return fmt.Errorf("%w: weights sum to %v, want 1.0 ± %v", ErrInvalidWeights, sum, eps)
	}
	return nil
}

// Score applies weights to a map of per-factor sub-scores in [0, 100]
// and returns an integer score in [0, 100] plus the derived Severity.
func Score(w Weights, factors map[string]int) (int, core.Severity, error) {
	if err := Validate(w.Values); err != nil {
		return 0, core.SeverityInfo, err
	}
	for name, v := range factors {
		if _, ok := w.Values[name]; !ok {
			return 0, core.SeverityInfo, fmt.Errorf("%w: %s", ErrUnknownFactor, name)
		}
		if v < 0 || v > 100 {
			return 0, core.SeverityInfo, fmt.Errorf("%w: %s=%d", ErrFactorOutOfRange, name, v)
		}
	}

	var total float64
	for name, weight := range w.Values {
		sub, ok := factors[name]
		if !ok {
			// Missing factors contribute zero (documented behaviour:
			// `elsereno explain` flags them).
			continue
		}
		total += weight * float64(sub)
	}
	score := int(math.Round(total))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, core.SeverityFromScore(score), nil
}

// Factors returns the canonical ordered list of factor names present
// in the weights map. Missing factors are excluded; extras are sorted
// after the defaults.
func (w Weights) Factors() []string {
	present := make(map[string]struct{}, len(w.Values))
	for k := range w.Values {
		present[k] = struct{}{}
	}
	out := make([]string, 0, len(w.Values))
	for _, d := range DefaultFactors {
		if _, ok := present[d]; ok {
			out = append(out, d)
			delete(present, d)
		}
	}
	extras := make([]string, 0, len(present))
	for k := range present {
		extras = append(extras, k)
	}
	sort.Strings(extras)
	return append(out, extras...)
}
