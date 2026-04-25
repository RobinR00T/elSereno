% ELSERENO-SCORING(5) ElSereno scoring | File formats
% ElSereno project
% 2026-04-19

# NAME

**elsereno-scoring** — scoring model and weights

# DESCRIPTION

ElSereno assigns each finding a score in the inclusive range **[0, 100]**
derived from six factors. Weights live in YAML files under
**internal/scoring/** and can be overridden per deployment.

# FACTORS

| Factor          | Default weight |
|-----------------|---------------:|
| protocol_risk   | 0.25           |
| exposure        | 0.20           |
| auth_state      | 0.20           |
| capability      | 0.15           |
| impact_class    | 0.10           |
| cve_exposure    | 0.10           |

The engine validates that weights sum to **1.0 ± 1e-9**.

# SEVERITY THRESHOLDS

| Severity  | Score      |
|-----------|------------|
| critical  | ≥ 80       |
| high      | ≥ 60, < 80 |
| medium    | ≥ 40, < 60 |
| low       | ≥ 20, < 40 |
| info      | < 20       |

# TRIAGE BUCKETS

The **`elsereno triage`** verb groups findings into four
buckets in priority order. The first match wins:

**quick_win**
:   severity ∈ {critical, high} AND **auth_state ≤ 10** — fast
    remediation, fix is usually "turn on auth".

**strategic**
:   severity == critical AND **impact_class ≥ 60** — long-
    horizon remediation plans.

**utility** (v1.13+)
:   severity ∈ {info, low} AND either the protocol is
    `banner` / `atmodem` (inventory plugins), OR **impact_class
    is absent or < 20**. Useful recon-grade signals (vendor
    banners, version leaks) separated from operational
    findings.

**routine**
:   everything else.

# STORAGE

Per-factor sub-scores are stored in **findings.factors** (JSONB). A run
can be re-scored without re-probing; the engine recomputes from the
stored sub-scores.

# SEE ALSO

*elsereno*(1), *elsereno.yaml*(5).
