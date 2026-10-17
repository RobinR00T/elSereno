---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 1500
---

# Security model

## Operator assumption
Single authorised operator on a workstation or jump host. Multi-user
collaboration is vNext.

## Threats
1. **Target-controlled bytes**: adversarial responses from scanned hosts.
   Mitigated by `internal/render.SafeBytes` for bytes, `internal/telemetry.
   SafeField` for strings at the log boundary.
2. **Credential exfiltration via process inspection**:
   `/proc/<pid>/environ`, `ps e`, shell history, argv. PITF-016, PITF-032.
3. **Audit tampering**: mitigated by JCS hash chain with genesis marker
   and tombstone-preserving purge; compact is a declared, auditable
   operation inserting a `chain_rebase` marker and skipping metadata
   entries (ADR-013, ADR-015, ADR-025).
4. **Supply chain**: reproducible builds (`-trimpath`, `-buildvcs=false`);
   `cosign` signing, SLSA L3 provenance, CycloneDX SBOM, `go-licenses`
   enforcement in CI.
5. **Race conditions on token rotation**: advisory lock + UPDATE/RETURNING
   pattern (PITF-026, ADR-014).

## Controls
- **Subprocess**: only via `internal/exec.SafeCommand(ctx, CommandSpec)`.
  Path allowlist, per-category validation, deterministic `--` separator
  (ADR-024, PITF-023).
- **Vault**: AES-GCM + Argon2id (`time=3, memory=64 MiB, threads=4`).
  Master key in `memguard.LockedBuffer`, unlock-once, zeroised on
  SIGINT/SIGTERM or `vault lock` (ADR-018).
- **CSRF key**: HKDF-SHA256 from vault master key,
  `info="elsereno/csrf/v1"`. Derived and unused: there is no CSRF
  token, and dev mode (loopback, no OIDC) has no authentication
  (PITF-087). Cross-site requests and DNS rebinding are refused by the
  browser guard (`internal/web/browserguard.go`, PITF-092). `serve` requires vault unlocked (ADR-017,
  PITF-021).
- **DB TLS**: required when not loopback (ADR-021).
- **Redaction**: zerolog hook with specific patterns +
  entropy heuristic with UUID-v1..v5 exclusion (PITF-004). Not wired:
  nothing builds that logger (PITF-087).
- **CSP nonces** per request; full security header set.
- **Rate limits** per-IP (loopback exempt) AND per-token.
- **Wire-layer write-ban in proxy plugins** (library code in every
  build: no command serves these handlers; the default build's `elsereno
  proxy` is a stub and the offensive `proxy listen` serves the gates in
  `offensive/write/<proto>` instead; PITF-087): Modbus and atmodem enforce
  the read-only policy at frame parse time, not at config. A misconfig
  cannot turn the proxy into a write proxy (ADR-030 for Modbus;
  atmodem `ForbiddenPrefixes` list for AT commands). The other plugins
  have their own default-build handlers (write-ban, filter, fail-closed,
  deny-all, or XOT's pass-through; per-plugin list in
  `docs/protocols/README.md`).
- **Sandbox** (offensive build only): `dial`, `exploit`, `harvest` and
  `write modbus send` confine their own process with seccomp-bpf on Linux
  and `sandbox_init` on macOS with cgo, and stop if it cannot be
  installed (NO_NEW_PRIVS alone only on architectures without a syscall
  table); `proxy listen` and `creds-check` run without it (ADR-042).
- **Secrets transport**: never argv, never herestring; env vars accepted
  only for CI/cron contexts with a rationale and a TTY warning (ADR-026,
  PITF-016, PITF-032).

## Data classification
- **Plain**: IPs, ports, banners → findings / evidence with truncation.
- **Sensitive (encrypted only)**: credentials, API keys, vault passphrase,
  IMSI/IMEI, phonebook entries. Written only to `creds_vault` or
  protocol-specific encrypted buffers; never to plain log or finding
  payload.

## Incident response
See `SECURITY.md` for disclosure process.
