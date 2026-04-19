---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 1500
---

# Scoring

ADR-006 defines a multi-factor scoring model that emits an integer in
`[0, 100]` per finding.

## Factors and default weights

| Factor | Default weight |
|--------|---------------:|
| `protocol_risk` | 0.25 |
| `exposure`      | 0.20 |
| `auth_state`    | 0.20 |
| `capability`    | 0.15 |
| `impact_class`  | 0.10 |
| `cve_exposure`  | 0.10 |

Weights are configurable via `internal/scoring/` YAMLs; the engine
validates that weights sum to 1.0 ± 1e-9.

## Severity thresholds

| Severity | Score range |
|----------|-------------|
| `critical` | `>= 80` |
| `high`     | `>= 60 && < 80` |
| `medium`   | `>= 40 && < 60` |
| `low`      | `>= 20 && < 40` |
| `info`     | `< 20` |

## Factor semantics (summary)

- **protocol_risk**: base risk of the protocol being exposed at all
  (writable industrial protocols rank highest).
- **exposure**: `internet` / `private` / `loopback`; degraded for scoped
  targets.
- **auth_state**: `none` / `default` / `credentials_present` /
  `authenticated_fail` — derived per protocol.
- **capability**: what the target permits (read-only vs write vs admin).
- **impact_class**: safety of disruption (SIS / lift alarm / HVAC …).
- **cve_exposure**: weighted known-CVE presence; capped to avoid single-CVE
  domination.

## Storage

`findings.factors` is a JSONB with all per-factor sub-scores in
`[0, 100]`. The engine recomputes `score` from the JSON, so re-scoring a
run does not require re-probing targets.
