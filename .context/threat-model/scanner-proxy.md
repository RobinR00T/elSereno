---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 1200
surface: scanner + proxy framework
---

# Threat model — scanner + proxy framework

Covers `internal/scanner/` (async probe orchestrator) and
`internal/proxy/` (generic TCP proxy with PreHook + PostHook). These
are the surfaces where ElSereno touches adversary-controlled bytes
at scale — an ICS PLC returning a malformed packet, or a Shodan hit
that sends the scanner into a degenerate retry loop.

## Scope

| In scope | Out of scope |
|----------|--------------|
| Outbound TCP probes | The probed device itself |
| In-process proxy framework (Hook interface) | Protocol-specific wire parsers (covered in their own threat docs) |
| Concurrency + rate limiting | Upstream reachability beyond the dial |
| Evidence capture + truncation | Evidence storage backend (see `vault-audit.md`) |

## S — Spoofing

| Threat | Mitigation | Code |
|--------|------------|------|
| Adversary spoofs IP to frame an authorised target | Scanner scope check (`internal/scope.Check`) runs pre-dial; scope.yaml CIDR is operator authority | `internal/scanner/scanner.go:Run` → `scope.Check` |
| Proxy client impersonates a downstream | Per-connection idle deadline closes stale; proxy does not authenticate clients today (operator-network trust zone) | `internal/proxy/framework.go:handle` |

## T — Tampering

| Threat | Mitigation | Code |
|--------|------------|------|
| Target-controlled bytes inject shell metachars into a log line | `internal/render.SafeBytes` sanitises every captured byte before it reaches a log / finding / evidence store | `internal/render/safebytes.go` |
| Hook rewrites bytes but leaks original-vs-replacement race | Hook's PreHook returns a replacement slice; framework copies atomically into the read buffer before forwarding | `internal/proxy/framework.go:Read` |
| Malformed wire frame crashes parser | Fuzz targets on every wire parser (Modbus, S7, ENIP, DNP3, IEC-104, HART-IP, XOT, atmodem) + nightly 30-min per-target fuzz matrix (F7 chunk 1) | `scripts/run-fuzz.sh`, `.github/workflows/nightly.yml` |

## R — Repudiation

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator denies having scanned a target | Every scan emits `protocol_probe` audit event with `target + plugin + score + factors`; retention keep-if-referenced keeps the reference as long as the finding exists | `internal/audit/events.go:EventProtoProbe` |
| Proxy session with no record | F3 proxy hooks include `LoggingHook` wired into the default config; session lifecycle logs session_start / session_end | `internal/proxy/logger.go` |

## I — Information disclosure

| Threat | Mitigation | Code |
|--------|------------|------|
| Target response contains credentials that leak into NDJSON output | Evidence is truncated at `evidence.max_payload_bytes`; `OriginalSHA256` only populated when truncated (ADR-007). Secrets in banner would still leak — mitigated at the redaction hook layer | `internal/retention/pruner.go` + telemetry hook |
| Shodan API key leaks via argv / env / log | Creds flow only through vault → `internal/creds.Retrieve` → HTTP Authorization header; never logged | `internal/inputs/shodan/client.go` |
| Temporal dedupe buffer leaks across runs | 5-min in-memory map, never persisted, zeroised on process exit | `internal/scanner/dedupe.go` |

## D — Denial of service

| Threat | Mitigation | Code |
|--------|------------|------|
| Adversary target responds with an infinite stream | Dial + IO deadlines enforced on every `net.Conn`; `io.ReadFull` bounded by frame-length fields | plugin `probe` funcs, `internal/proxy/framework.go` |
| Scanner overwhelmed by huge input list | `errgroup` with global + per-host `semaphore.Weighted`; `rate.Limiter` token-bucket | `internal/scanner/scanner.go` |
| Target causes per-host hot spot | Per-host semaphore (`newHostSemaphore`) caps concurrent probes against the same IP | `internal/scanner/hostsem.go` |
| Retry storm on persistent failure | Circuit breaker (F1 chunk 3) opens after N consecutive failures and exponential backoff with jitter | `internal/scanner/scanner.go:withRetries` |

## E — Elevation of privilege

| Threat | Mitigation | Code |
|--------|------------|------|
| Proxy ferries a write frame the operator didn't authorise | Wire-layer write-ban in Modbus + atmodem + 7 F4 plugins (ADR-030 + ADR-040); refusal is protocol-native | `internal/protocols/modbus/modbus.go:ProxyHandler`, `internal/protocols/s7/s7.go:writeBanHandler`, etc. |
| Scanner plugin given wrong target scope | `scope.Check` runs inside the scanner goroutine before dial; out-of-scope targets never reach the plugin's `Probe` | `internal/scanner/scanner.go:Run` |
| Non-loopback proxy bind without auth | Proxy framework binds `Listen` address caller-supplied; operator responsibility documented in proxy doc. F8 adds an explicit loopback-only default | `internal/proxy/framework.go:New` |

## Residual risk (accepted)

- **Plugin hooks are trusted**: the framework does not sandbox `Hook`
  implementations. A malicious plugin could exfiltrate bytes by
  writing to disk inside `PreHook`. Mitigated by code review +
  build-tag gate on offensive plugins.
- **CIDR-only scope**: scope.yaml ranges are network-layer; ElSereno
  cannot tell two subnets apart if they share CIDR but differ in
  VLAN. Operator responsibility.
- **No egress firewalling**: scanner can reach any IP the host's
  route table allows. F8 ticket for an operator-level egress
  allowlist enforced by the scanner wrapper.
