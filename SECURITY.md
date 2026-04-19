# Security policy

## Reporting a vulnerability

Please report suspected security vulnerabilities by email to
**daniel.solis@zynap.com** with the subject line `[elsereno security]`.
Please **do not** open a public GitHub issue for vulnerabilities.

We aim to acknowledge reports within 72 hours and to provide a remediation
timeline within 14 days.

## Supported versions

Until the 0.1.0 release, only `main` is supported. After 1.0.0, the latest
minor line is supported for security fixes.

## Threat model (summary)

ElSereno is operated by a single authorised operator on a workstation or
jump host, against targets where explicit authorisation exists. The threat
surface includes:

- **Target-controlled bytes**: responses from scanned hosts are adversarial.
  All rendering goes through `internal/render.SafeBytes`; all logging of
  target-derived strings goes through `internal/telemetry.SafeField`.
- **Credential leakage**: API keys, vault passphrases, and web tokens must
  never be emitted to logs, argv, herestrings, or (where avoidable) env
  vars. See PITF-016 and PITF-032.
- **Audit integrity**: the audit log is a JCS hash chain. Tombstone purge
  preserves the chain; compact is a declared, auditable operation that
  skips metadata entries (ADR-013, ADR-015).
- **Supply chain**: `goreleaser` builds are reproducible (`-trimpath`,
  `-buildvcs=false`); releases are signed with `cosign`; SBOM via
  `cyclonedx-gomod`; SLSA L3 provenance via `slsa-github-generator`.
- **Subprocess exec**: only via `internal/exec.SafeCommand` with a typed
  `CommandSpec{Name, Flags, Positional}` and deterministic `--` separator
  (ADR-024).

## Security controls (excerpt)

- Postgres TLS required when not loopback (ADR-021).
- Web dashboard: Bearer for `/api/v1/*`, cookie + CSRF (HKDF from vault
  master key) for HTML (ADR-014, ADR-017).
- Vault: AES-GCM + Argon2id, unlock-once in `memguard.LockedBuffer`,
  zeroised on SIGINT/SIGTERM or `vault lock` (ADR-018).
- Rate limits per-IP (100/min, loopback exempt) **and** per-token (300/min).
- Rand only via `crypto/rand`.
- `http.Server` with full timeouts (5s/30s/30s/120s, 16 KiB header limit).
- Audit entries are canonicalised with JCS (RFC 8785) over
  `id, occurred_at, actor, event_type, payload, prev_hash`.
- `crypto/rand` for all cryptographic material.

## Responsible use

ElSereno is a tool for authorised security work. Operators are responsible
for obtaining and documenting authorisation for any target. See `LEGAL.md`
for the acceptable-use policy and applicable legal framing.
