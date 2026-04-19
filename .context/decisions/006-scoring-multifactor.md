---
id: 006
title: Scoring 0–100 multi-factor with named weights
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-006: Scoring 0–100 multi-factor with named weights

## Context
A single "critical / not critical" boolean is useless for triage. A
free-form severity is ungovernable. We need a numeric scale with
explainable sub-factors.

## Decision
Findings receive an integer score in `[0, 100]` computed from six named
factors:

| Factor | Default weight |
|--------|---------------:|
| `protocol_risk` | 0.25 |
| `exposure`      | 0.20 |
| `auth_state`    | 0.20 |
| `capability`    | 0.15 |
| `impact_class`  | 0.10 |
| `cve_exposure`  | 0.10 |

Severities are derived from the score:

| Severity | Threshold |
|----------|----------:|
| `critical` | `>= 80` |
| `high`     | `>= 60` |
| `medium`   | `>= 40` |
| `low`      | `>= 20` |
| `info`     | `< 20` |

Per-factor sub-scores are stored as JSONB in `findings.factors`; the engine
can re-score a run without re-probing.

## Consequences
### Positive
- Explainable: `elsereno explain <finding>` prints the factor breakdown.
- Tunable: weights live in YAML; deployments can override.
- Storable: JSONB factors make audit-friendly diffs trivial.

### Negative / trade-offs
- Weight tuning is a moving target; we pin the defaults with an ADR.
- The CVE factor risks double counting if the protocol factor already
  reflects known-bad families; we cap `cve_exposure` to mitigate.

## Alternatives considered
- CVSS-style vector: expressive but mismatched for ICS-specific factors
  (no "impact to safety loop", no "wardialing blast radius").

## References
- `.context/scoring.md`; `internal/scoring/`.
