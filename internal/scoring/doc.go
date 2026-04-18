// Package scoring implements the multi-factor scoring engine (ADR-006).
// Factor weights are loaded from YAML; the engine validates that
// weights sum to 1.0 +/- 1e-9 and computes score in [0, 100].
package scoring
