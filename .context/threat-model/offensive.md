---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 1500
surface: offensive
---

# Threat model — offensive surface

Covers `offensive/confirm/` (triple-confirm wrapper),
`offensive/write/{modbus,s7,enip,bacnet}/`,
`offensive/exploits/` (CVE harness + CVE-2015-5374 +
CVE-2019-10953), `offensive/dial/`, `offensive/harvest/`, and
`offensive/sandbox/`. This is the highest-stakes surface: every
byte emitted here has a physical-world consequence.

## Scope

| In scope | Out of scope |
|----------|--------------|
| `-tags offensive` code paths | Default-build plugins (no offensive capability) |
| Triple-confirm token derivation | DB-backed audit delivery (F7+ carry-over) |
| seccomp-bpf profile load | BPF filter bytecode (F7+ carry-over) |
| Dial hard block + scope.blocked_numbers | Wardialing batch (vNext) |

## S — Spoofing

| Threat | Mitigation | Code |
|--------|------------|------|
| Attacker forges a confirm token on a different workstation | Token = HMAC-SHA256 with a key derived via HKDF from *this* vault's master key; different vault → different token | `offensive/confirm/confirm.go:ExpectedToken` |
| Replay of a previously-captured token | Token is per-argv (includes target + operation + payload hash); a re-used token on a different target fails `ErrTargetMismatch` | ADR-039 |
| Operator tricked into running against a different target | `--confirm-target` must byte-match argv target; operator pasting the token without reading the `--target` field still fails the check | ADR-039 |
| Exploit module spoofed with an ID colliding with a legitimate CVE | Registry `Register` panics on duplicate ID — fatal at init, never a silent collision | `offensive/exploits/harness.go:Register` |

## T — Tampering

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator edits the built payload between dry-run and real-run | Payload hash recomputed in `Authorize`; any byte change yields a different hash → a different expected token → `ErrTokenMismatch` | `offensive/confirm/confirm.go:Authorize` |
| Attacker corrupts the write PDU in-flight | Build is pure and deterministic; the PDU is built from the authorised Request struct inside `Execute`, not from an operator-editable file | `offensive/write/modbus/write.go:Execute` |
| Offensive payload exfil through a logging side channel | `AuditEvent.PayloadHash` is hex; the raw payload bytes never appear in the audit event | ADR-039 |
| Short-dial bypass via scope.yaml edit | ADR-041 gate 1 is code-level, not config; no YAML edit can override the ≤3-digit block | `offensive/dial/validate.go:Validate` |

## R — Repudiation

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator denies issuing a destructive write | Every `Authorize` call emits one of `offensive_allowed`, `offensive_denied`, `offensive_failed` with hashed payload + target + operation; denied attempts are retained | `offensive/confirm/confirm.go:audit` |
| Disputed dial | `offensive/dial.Validate` feeds the same Authorize chain under `CategoryDial`; denied dials audited same way | ADR-041 |
| Credential harvest hit without a record | Harvest probers emit `offensive_harvest` on hit + `offensive_denied` on attempt failure; credentials stored in vault via `creds.Store` which also audits | `offensive/harvest/harvest.go` |

## I — Information disclosure

| Threat | Mitigation | Code |
|--------|------------|------|
| Harvested credential leaks via argv / shell history | Creds written to vault via `creds.Store`; never echoed to stdout, no `--print-cred` flag | `cmd/elsereno/cmd_harvest_offensive.go` |
| Exploit payload byte dump reveals 0-day details | Only public, stable CVEs ship (CVE-2015-5374, CVE-2019-10953 — both DoS-only); repo publishes payload bytes because the vendor advisory already does | `offensive/exploits/cve_*/module.go` |
| Dial number leaked in logs | `offensive/dial.Normalise` stores the normalised digits-only form; SafeField on the audit event's target field | `offensive/dial/validate.go:Normalise` |
| Confirm token in audit event | `AuditEvent` structure never carries the token — only the payload hash | `offensive/confirm/confirm.go:AuditEvent` |

## D — Denial of service

| Threat | Mitigation | Code |
|--------|------------|------|
| Fuzzing the confirm wrapper to brute-force a token | Constant-time `hmac.Equal` comparison + 32-hex token = 2^128 search space; rate limited at the CLI level (one token = one invocation) | `offensive/confirm/confirm.go:Authorize` |
| Operator accidentally stampedes an ICS target | Write plugins are dry-run by default; real invocation requires all three fences PLUS the operator typed `--target` explicitly | ADR-039 |
| Exploit payload blows past MTU and gets fragmented | Exploit packets are short (18 bytes for CVE-2015-5374, 24 bytes for CVE-2019-10953); no fragmentation risk | payloads in `offensive/exploits/cve_*/module.go` |
| Dial-guard normalisation path exploited to DoS | `Normalise` is O(n) on input bytes, bounded by operator input size; no regex backtracking | `offensive/dial/validate.go:Normalise` |

## E — Elevation of privilege

| Threat | Mitigation | Code |
|--------|------------|------|
| Build tag bypassed via `-tags ""` | Offensive code literally does not compile into the default binary; operator must pass `-tags offensive` | `//go:build offensive` on every file under `offensive/` |
| Scope widened to cover a production target | Triple-confirm still fires; scope is gate 2, confirm is gate 3, build tag is gate 0 — operator must cross every gate | ADR-039 + ADR-041 |
| Subprocess escape (exploit helper binary) | `offensive/sandbox.Load` installs `PR_SET_NO_NEW_PRIVS`; F7+ adds BPF syscall filters per profile | `offensive/sandbox/sandbox_linux.go` |
| Harvest prober returns a cred that's actually attacker-controlled MITM | Operator verifies the target out-of-band; audit event records the banner bytes so a MITM banner is post-hoc detectable | harvest probers |

## Residual risk (accepted)

- **DB-backed audit writer not wired**: offensive CLI is dry-run
  today; operators can still run the real-mode bytes manually.
  Carry-over to F7+. Until then, operators relying on the audit
  chain must run the file-backed auditor documented in ADR-039.
- **No per-op cooldown**: an operator who legitimately unlocks the
  vault could mint a burst of tokens. Acceptable because the op is
  trusted within the triple-confirm model; F8 may add a per-op
  rate-limiter.
- **Public-CVE payloads are reproducible**: anyone reading the
  source can reproduce the exploits. This is the *point* — the
  project is for authorised pentesting; CISA ICSA-19-122-02 + SSA-
  732541 publish the same payloads.
- **macOS degraded sandbox**: `seccomp-bpf` is Linux-only; macOS
  returns `Availability.Available=false`. Production operators must
  use Linux (documented in SECURITY.md).
