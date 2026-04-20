---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 1000
surface: subprocess + scope
---

# Threat model — subprocess + scope

Covers `internal/exec/` (the single `SafeCommand` choke point) and
`internal/scope/` (scope.yaml authority). These two packages
together answer "is this command / target allowed, and is the
binary we're about to spawn actually the one we think it is?"

## Scope

| In scope | Out of scope |
|----------|--------------|
| `internal/exec.SafeCommand` spawn path | sub-subprocess spawns (child's children) |
| `--no-allowlist` bypass flow + audit | `fork` / `clone` from goroutine contexts (n/a) |
| `internal/scope.Check` + `CheckProtocol` + `CheckDial` | scope.yaml editor hygiene |
| CIDR v4 / v6 matching | DNS resolution — handled at the scanner layer |

## S — Spoofing

| Threat | Mitigation | Code |
|--------|------------|------|
| PATH manipulation causes wrong binary to run | `SafeCommand` calls `exec.LookPath` then validates the resolved absolute path lives under one of `AllowedPaths` (default `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`) | `internal/exec/safecommand.go:resolveBinary` |
| Operator dropped a trojan in `~/bin` on PATH | Default allowlist excludes home-dir paths; operator must supply `AllowedPaths` explicitly to widen | ADR-024 |
| Scope file replaced with forged CIDR list | `scope.Load` reads from disk; integrity check is the operator's responsibility (git tracked). ADR-038 carry-over: scope.yaml signature verify | — (F8) |

## T — Tampering

| Threat | Mitigation | Code |
|--------|------------|------|
| Injected flag string like `-x;rm -rf /` | `flagPattern` regex: `^-[A-Za-z0-9][A-Za-z0-9._=:/+-]*$`; semicolons, backticks, pipes, nuls, newlines all rejected by `validateFlags` | `internal/exec/safecommand.go:validateFlags` |
| Positional argument with shell metachars | `DefaultPositionalValidator` rejects `;|&$\`\n\r\x00`; commands can plug a stricter validator per-command | `internal/exec/safecommand.go:DefaultPositionalValidator` |
| Argv "--" separator missing, flag-as-positional confusion | `SafeCommand` inserts `--` deterministically between flags and positional args | `internal/exec/safecommand.go:SafeCommand` |
| Scope.yaml mutated mid-run | `scope.Load` returns a snapshot; each scanner run uses the snapshot it loaded at start; mutations require restart | `internal/scope/scope.go:Load` |

## R — Repudiation

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator claims they never bypassed the allowlist | `CommandSpec.AllowAnyPath=true` mandates a `BypassAuditor` whose `RecordBypass` must succeed before spawn; absence or failure fails closed | `internal/exec/safecommand.go` F5 chunk 6 |
| Disputed scope decision | `scope_applied` audit event fired when a run loads a scope.yaml | `internal/audit/events.go:EventScopeApplied` |

## I — Information disclosure

| Threat | Mitigation | Code |
|--------|------------|------|
| Secret in argv visible via `ps e` / `/proc/<pid>/cmdline` | CLAUDE.md rule + ADR-026 + PITF-032: never secrets via argv; passphrase via 0600 file or prompt only | CLAUDE.md |
| Subprocess environment leaks parent secrets | `SafeCommand` inherits env; callers can clear before running. Today we rely on operator hygiene; F8 adds `EnvAllowlist` to `CommandSpec` | — (F8) |
| Subprocess stdout/stderr contains secrets | Caller owns the streams; scanner pipes through redaction hook before logging | `internal/telemetry/redact.go` |

## D — Denial of service

| Threat | Mitigation | Code |
|--------|------------|------|
| Subprocess never exits | Caller provides a ctx with deadline; `SafeCommand` returns `*exec.Cmd` and caller drives `Start`+`Wait` with the ctx | `internal/exec/safecommand.go` |
| Scope check on huge target list degrades scanner | Scope ranges walked linearly per target; acceptable up to a few hundred entries; documented in brief §15 | — |

## E — Elevation of privilege

| Threat | Mitigation | Code |
|--------|------------|------|
| Attacker runs a binary outside allowlist via `--no-allowlist` without audit | `AllowAnyPath=true` path requires non-nil `BypassAuditor`; failing to wire one returns `ErrBypassAuditRequired` | `internal/exec/safecommand.go:SafeCommand` |
| Subprocess regains setuid privilege | Linux `PR_SET_NO_NEW_PRIVS` installed by `offensive/sandbox.Load` for offensive subprocesses (F5 chunk 5) | `offensive/sandbox/sandbox_linux.go` |
| Symlink trick: scope.yaml symlink to `/etc/passwd` | `scope.Load` reads via `os.ReadFile` — Go's stdlib follows symlinks intentionally (text config, not secret). No mitigation needed because the content is parsed as YAML; mis-shaped content fails `yaml.KnownFields(true)` | PITF-010 |

## Residual risk (accepted)

- **Operator trusted**: bypass audit catches the action but an
  operator with root on the box can still edit the audit chain's
  DB directly. This is the same residual as in `vault-audit.md`.
- **Scope.yaml integrity**: no cryptographic signature yet. vNext.
- **Subprocess sandbox on macOS**: gracefully degraded (ADR-042);
  operators running offensive flows in production MUST use Linux.
