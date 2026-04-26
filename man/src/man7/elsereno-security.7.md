% ELSERENO-SECURITY(7) ElSereno security model | Miscellaneous
% ElSereno project
% 2026-04-26

# NAME

**elsereno-security** — threat model, controls, and flags

# THREAT MODEL

ElSereno is operated by a single authorised operator on a workstation or
jump host. The primary adversaries are:

- **Target-controlled bytes** — responses from scanned hosts. Mitigated
  by *render.SafeBytes* (bytes) and *telemetry.SafeField* (strings at
  the log boundary).
- **Credential exfiltration** — shell history, argv, **ps e**,
  */proc/<pid>/environ*. Never pass secrets on argv or via herestring.
  Env vars leak via */proc*; use a 0600 file for persistent secrets or
  the encrypted vault (*elsereno creds store*).
- **Audit tampering** — the audit log is a JCS hash chain with a genesis
  marker, tombstoning purge, and an auditable rebase on compact.
  Cross-process safety: writers acquire **flock(LOCK_EX)** before
  Append / appendVerbatim and resume from the latest tail under the
  lock so two ElSereno processes (e.g. **serve** + **proxy listen**)
  cannot race the chain (Linux + macOS, v1.15+).
- **Supply-chain** — reproducible builds (**-trimpath**,
  **-buildvcs=false**); free-tier flow since v1.8 ships GPG-signed
  tag (key **ACE3B86BACACE7D6**) + SHA-256 + CycloneDX SBOM via
  **goreleaser local + gh release create**; **cosign** keyless +
  SLSA L3 + GHCR remain available behind GitHub Actions billing.
  **go-licenses** enforced in **make sec**.

# CONTROLS

**Subprocess**
:   Only via *internal/exec.SafeCommand* with *CommandSpec{Name, Flags,
    Positional}*. The **--** separator is always present.

**Vault**
:   AES-GCM + Argon2id (**time=3, memory=64 MiB, threads=4**). Master
    key is **unlock-once**, cached in *memguard.LockedBuffer*, zeroised
    on **vault lock** or SIGINT / SIGTERM.

**CSRF**
:   Key derived from the vault master key via HKDF-SHA256 with
    **info="elsereno/csrf/v1"**. **serve** requires the vault to be
    unlocked.

**Database TLS**
:   **database.tls_required** ∈ {**auto**, **always**, **disable**};
    **disable** is rejected at runtime on non-loopback hosts.

**Rate limiting**
:   Per-IP 100/min (loopback exempt) AND per-token 300/min; the more
    restrictive limit wins.

**HTTP server**
:   Full timeouts (**5s**/**30s**/**30s**/**120s**) and 16 KiB header
    limit.

**Audit log**
:   JCS canonicalised over **id, occurred_at, actor, event_type,
    payload, prev_hash**. Genesis **prev_hash = 0x00..00**. Tombstone
    purge preserves the chain; compact inserts a **chain_rebase** marker
    and skips metadata entries.

# FLAGS AND ENVIRONMENT

**-tags offensive** (build)
:   Enables writes, exploits, harvesting, and dialling. Writes require
    triple confirmation. Dialling additionally requires
    **--dial-allowed**; ≤ 3-digit numbers are hard-blocked.

**ELSERENO_VAULT_PASSPHRASE** (env)
:   Emits a warning when a TTY is present; prefer **vault unlock** or a
    0600 file.

# EXIT CODES

Signals exit with **128 + signum**: SIGINT → **130**, SIGTERM →
**143**. A second signal during drain exits immediately with the same
code.

**proxy listen** (offensive build) additionally maps **SIGHUP →
exit 75** (*EX_TEMPFAIL*) so a supervisor (systemd / runit / s6)
can distinguish reload-style exit from a real crash via
**RestartPreventExitStatus=** and re-execute with a fresh
allowlist + freshly minted confirm-token (v1.15+).

# SEE ALSO

*elsereno*(1), *elsereno.yaml*(5), *elsereno-scope*(5).
