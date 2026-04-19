---
id: 039
title: Offensive build — architecture & triple-confirm wrapper
status: accepted
date: 2026-04-19
phase: F5
---

# ADR-039: Offensive build — architecture & triple-confirm wrapper

## Context
F5 introduces writes to live OT devices (Modbus, S7, CIP, BACnet),
two public-stable CVE exploits, credential harvest, and dial. Every
operation in this set can cause physical impact or violate AUP. The
default-denial posture of F0–F4 (read-only, wire-level write-ban in
Modbus/atmodem, pass-through for the rest) was the correct "no
surprise" stance. F5 opens specific, auditable escape hatches that
never widen the default.

The architecture must satisfy, simultaneously:
- An operator who `go build`s the default flavour cannot accidentally
  cause a write (compile-time fence).
- An operator who compiles `-tags offensive` still cannot cause a write
  without a deliberate, per-invocation signal.
- Every write leaves a tamper-evident audit trail — including the denied
  attempts.
- The wire layer remains the last line of defence; a bug in a higher
  layer must not slip a frame through.

## Decision

### Build-tag fence
All offensive code lives under the `offensive/` top-level package (not
`internal/`) and every file carries `//go:build offensive`. The default
build tree does not import anything from `offensive/`. Registration
happens through `cmd/elsereno/plugins_offensive.go` (also `//go:build
offensive`). This is the same policy ADR-004 established for the
CLI scaffolding; ADR-039 confirms it for the implementation.

### Triple-confirm wrapper
Every mutating operation passes through
`offensive/confirm.Authorize(ctx, Mutation, Confirm) error`. The call
succeeds iff **all three** of these hold:

1. `c.AcceptsWrites == true` — set by the `--accept-writes` CLI flag
   (no default, no env var).
2. `c.ConfirmTarget == m.Target.String()` — set by
   `--confirm-target host:port`; must match the argv-provided target
   byte-for-byte.
3. `c.ConfirmToken == ExpectedToken(m)` — set by `--confirm-token`.
   `ExpectedToken(m)` is `HMAC-SHA256(masterKey, proto || 0x00 || op ||
   0x00 || target || 0x00 || payloadHash)` truncated to the first 16
   hex bytes (32 chars). `masterKey` is derived via HKDF from the vault
   master key with `info="elsereno/offensive/confirm/v1"`. The vault
   MUST be unlocked — otherwise the token cannot be computed and
   `Authorize` fails with `ErrVaultLocked`.

Dry-run prints the expected token (requires `--accept-writes` already
present). The operator re-runs the same argv with `--confirm-token
<value>` to actually fire the mutation. There is no fourth step.

### Wire-layer enforcement survives
The Modbus read-only proxy (ADR-030) remains the authoritative gate
for traffic that flows through the proxy endpoint. When `-tags
offensive` is compiled, the proxy can be put into **write-gated mode**
by `elsereno proxy modbus --accept-writes --gate-writes`, which
replaces the IllegalFunction short-circuit with a per-frame triple-
confirm check against an in-memory allowlist (protocol+op+target)
populated via the CLI. The default proxy behaviour (even under
`-tags offensive`) remains the read-only policy.

### Audit contract
Every `Authorize` call — allowed, denied, or errored — emits an audit
event with `event_type` in `{offensive_attempt, offensive_allowed,
offensive_denied, offensive_failed}`, payload contains
`{proto, op, target, denied_reason}`; `payloadHash` is stored but the
plaintext payload never is. Denied attempts still appear in the chain
so they cannot be erased by the operator.

### Scoping: writes vs. exploits vs. harvest vs. dial
All four offensive categories route through the same `Authorize`
wrapper. Differences are declared in the `Mutation.Category`:
- `CategoryWrite` — writes to live devices.
- `CategoryExploit` — CVE modules.
- `CategoryHarvest` — credential-list based probes (Telnet, FTP,
  HTTP-Basic, SNMPv1/v2c).
- `CategoryDial` — outbound PSTN dial (F5 per ADR-041).

## Consequences

### Positive
- Four independent fences (tag, flag, confirmed-target, confirmed-
  token); bypassing any one without the others fails closed.
- Token derivation from vault means the operator cannot script past
  triple-confirm without unlocking the vault (attended or
  deliberately via `vault unlock`).
- Denied attempts are still audit-visible; we will catch fuzzing
  attempts against the triple-confirm itself.
- Same wrapper for writes / exploits / harvest / dial → one code path
  to review and fuzz.

### Negative / trade-offs
- Slightly ceremonial UX for operators: one dry-run to read the token,
  one real run to fire it. Documented in `docs/offensive-workflow.md`.
- The token is per-argv, not per-connection: if the operator reuses the
  same token within the replay window (15 s) it still fires. Documented;
  the argument is that the operator who just pasted it is the same one
  about to fire.

## Alternatives considered
- **Config-driven permit list**: rejected. An edited scope.yaml that
  opens a write rule is indistinguishable from a typo; the safety
  argument dominates.
- **4+ confirmations**: rejected. Diminishing returns, and operators
  who have to do six steps start scripting past the UX.
- **Per-connection random nonce**: rejected for F5; adds
  round-trip complexity without substantially changing the bypass
  cost. Revisit if a field incident points at token replay.

## References
- ADR-004 (build-tag scaffolding).
- ADR-010 (sandbox; F5 supplementary in ADR-042).
- ADR-030 (Modbus wire-layer write-ban).
- `offensive/confirm/confirm.go`.
- `.context/security-model.md`.
