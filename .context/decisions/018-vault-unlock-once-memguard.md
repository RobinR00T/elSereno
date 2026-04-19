---
id: 018
title: Vault unlock-once, master key cached in memguard
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-018: Vault unlock-once, master key cached in memguard

## Context
Prompting for the vault passphrase on every credential access is unusable
(a scan can touch thousands of targets — PITF-005). Keeping the master
key in plain Go memory leaks it to core dumps and swap.

## Decision
- `vault unlock` derives the master key from the passphrase (Argon2id:
  `time=3, memory=64 MiB, threads=4`).
- The master key lives in `memguard.LockedBuffer` for the lifetime of the
  process.
- `vault lock` zeroises the buffer (PITF-028: reversible operation has
  an explicit reversion).
- SIGINT/SIGTERM also zeroise the buffer before exit.
- `elsereno doctor` verifies `memguard` `mlock` capability; on macOS the
  library may fall back to software protection — doctor emits a warning.

## Consequences
### Positive
- Usable in batch scans.
- Secrets resist core-dump and swap leakage on Linux.
- `vault lock` allows the operator to drop privileges without restart.

### Negative / trade-offs
- `memguard`'s macOS `mlock` equivalent is best-effort.
- A second "unlock-once" design could be implemented later (e.g. via
  OS keychain); the current approach stays portable.

## Alternatives considered
- Keep passphrase in env var: leaks via `/proc/<pid>/environ` and `ps e`
  (PITF-032).
- Re-derive per access: kills UX.

## References
- PITF-005, PITF-028, PITF-032; ADR-017.
