---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 1000
surface: telemetry + canary
---

# Threat model — telemetry + canary webhook

Covers `internal/telemetry/` (zerolog + redaction hook + Prometheus
+ OTel tracer F7 chunk 3) and `internal/canary/` (webhook emitter
for scope violations + offensive denials). Both surfaces emit
data OUT of the process; the risk is they leak secrets or become
a side-channel for an attacker to influence the operator.

## Scope

| In scope | Out of scope |
|----------|--------------|
| zerolog JSON log lines | Downstream SIEM filtering |
| Prometheus `/metrics` emission | Prometheus alertmanager policy |
| OTel span export via OTLP/stdout | Collector / Jaeger / Tempo backend |
| Canary webhook POST body + signature | Receiver-side auth / replay protection |

## S — Spoofing

| Threat | Mitigation | Code |
|--------|------------|------|
| Attacker forges a canary webhook the operator trusts | Optional HMAC-SHA256 signature in `X-Elsereno-Signature` derived from a vault HKDF sub-key; receiver verifies and rejects mismatched bodies | `internal/canary/canary.go:Send` |
| Forged OTel span injected into the collector | OTel collector auth is out of scope (it's the operator's Jaeger/Tempo/Otel-collector configuration); project ships without authentication headers by default | — |
| Forged log line impersonating another component | Each line carries `service.name` + goroutine ID; tamper-resistance is the SIEM's problem | `internal/telemetry/logger.go` |

## T — Tampering

| Threat | Mitigation | Code |
|--------|------------|------|
| Canary body altered after HMAC signing | Signature is over the exact bytes sent; any change → `X-Elsereno-Signature` no longer verifies | `internal/canary/canary.go:Send` |
| Log line mutated in flight | zerolog writes are immediate + atomic per `log.Info()`; transport-layer integrity is the operator's (TLS to SIEM, etc.) | `internal/telemetry/logger.go` |
| OTel span attribute tampered between export + collector | OTLP/gRPC supports mTLS — operator's deployment responsibility. Default exporter is `none`; explicit opt-in | `internal/telemetry/tracer.go` |

## R — Repudiation

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator claims a canary was never sent | Canary Sender returns typed errors; caller logs the attempt with the canary's Kind + Target + Reason | `internal/canary/canary.go` |
| OTel span lost due to exporter failure | Batched exporter with `BatchTimeout=5s`; failures surface via `tp.Shutdown` return value; operator must log it | `internal/telemetry/tracer.go:InitTracer` |

## I — Information disclosure

| Threat | Mitigation | Code |
|--------|------------|------|
| Secret leaks into a log message (API key, bearer) | zerolog redaction hook with specific-pattern match + Shannon entropy >4.5 bits/byte + UUID v1-v5 exemption | PITF-004, `internal/telemetry/redact.go` |
| Prometheus label cardinality explosion with ASN / country values | Label sanitiser restricts ASN to numeric, country to ISO 3166-1 (PITF-017) | `internal/telemetry/metrics.go` |
| OTel span attribute contains target banner (potential secret) | Scanner span attaches only `target.address` + `target.port` + `scanner.attempts` — no banner bytes | `internal/scanner/scanner.go:withRetries` |
| Canary body carries the raw offending payload | `Event` fields are typed (Kind, Actor, Target, Reason); attacker-supplied bytes never passed through verbatim | `internal/canary/canary.go:Event` |
| Webhook secret leaked via log on signing failure | HMAC key never logged; failures wrap into typed errors without key content | `internal/canary/canary.go:Send` |

## D — Denial of service

| Threat | Mitigation | Code |
|--------|------------|------|
| Canary webhook endpoint slow → scanner blocks | `Sender.Send` uses an `http.Client` with 5 s Timeout; caller logs and continues on `ErrNon2xx` | `internal/canary/canary.go:New` |
| OTel exporter backpressure stalls the scanner span chain | Batched exporter drops spans when the queue is full; no-op tracer fallback means worst case is a dropped span | OTel SDK internals |
| Log output volume causes disk fill | zerolog goes to stderr; operator's systemd / container runtime handles rotation | operator deployment |

## E — Elevation of privilege

| Threat | Mitigation | Code |
|--------|------------|------|
| Canary receiver gains the HMAC key and forges events backward | Key is HKDF-derived from vault master; it never leaves the process. A compromised receiver can only replay what it already saw | `internal/canary/canary.go:New` |
| OTel collector becomes a pivot to the operator network | Exporter is opt-in (`OTEL_TRACES_EXPORTER=none` default); operator consciously connects it | `internal/telemetry/tracer.go:InitTracer` |

## Residual risk (accepted)

- **Receiver replay**: the canary signature proves origin but not
  freshness. Receivers that need replay protection should add a
  nonce / timestamp check. Documented in `internal/canary/canary.go`.
- **OTel exporter defaults are TLS-free**: `otlptracegrpc.WithInsecure()`
  is the default; operators deploying across network boundaries must
  switch to mTLS. F8 ticket to validate the collector endpoint is
  loopback before allowing `WithInsecure`.
- **Prometheus `/metrics` public-by-default**: exposed at the same
  port as the dashboard; the Bearer middleware does not gate
  `/metrics` today (operators may scrape without auth). F8 adds
  an optional auth mode.
