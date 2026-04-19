---
id: 024
title: SafeCommand with explicit CommandSpec{Name, Flags, Positional}
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-024: SafeCommand with explicit `CommandSpec{Name, Flags, Positional}`

## Context
Subprocess invocation is the most common source of shell-injection and
flag-injection bugs. An earlier sketch passed `argv []string` directly
and tried to inject the `--` separator via a string scan, which is
brittle.

## Decision
- `internal/exec.SafeCommand(ctx context.Context, spec CommandSpec) error`
  is the **only** way to spawn a subprocess.
- `CommandSpec{Name string; Flags []string; Positional []string}`.
- Final argv is assembled deterministically as:
  `[Name] ++ Flags ++ ["--"] ++ Positional` — the `--` is always present
  (PITF-023).
- `Name` is validated via `exec.LookPath` and the resolved path is
  checked against `exec.allowed_paths` (default
  `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`).
- Each `Flags[i]` must start with `-` and must not contain any of
  `;|&$`, newlines, nul bytes, or backticks.
- Each `Positional[i]` is validated per command (e.g. IP/CIDR for nmap
  targets via `netip.ParseAddr` / `ParsePrefix`).
- `exec.LookPath` is called, never shell=true; the only `//nolint:gosec
  G204` is localised to the `SafeCommand` implementation with an
  explanatory comment.

## Consequences
### Positive
- Flag injection is structurally impossible (the `--` separator is
  always present).
- Path spoofing is mitigated by the allowlist.
- One place to audit for subprocess safety.

### Negative / trade-offs
- Callers can no longer pass a free-form argv; every use site builds a
  `CommandSpec`. This is by design.

## Alternatives considered
- Free-form argv with a linter rule: catch-rate too low for a defensive
  tool.
- `syscall.Exec`: skips env and working-directory nuances we actually
  need.

## References
- PITF-023; `internal/exec/`; `CONTRIBUTING.md`.
