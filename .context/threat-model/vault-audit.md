---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 1200
surface: vault + audit
---

# Threat model — vault + audit chain

Covers `internal/creds/` (AES-GCM + Argon2id + HKDF vault) and
`internal/audit/` (JCS hash chain). These are the project's crown
jewels: the vault holds every third-party API token + every harvested
credential; the audit chain is the evidence trail that backs every
ICS write an operator ever issues. A compromise of either is
catastrophic.

## Scope

| In scope | Out of scope |
|----------|--------------|
| Local disk vault file (`~/.elsereno/vault.v1.bin`) | Backup copies (F7 chunk 6 owns) |
| Audit DB table + JCS chain | Audit export channels (CEF / syslog — see `telemetry-canary.md`) |
| Vault passphrase entry | TTY hardening outside the process |
| HKDF sub-key derivations | HSM / KMS integration (vNext) |

## S — Spoofing

| Threat | Mitigation | Code | ADR |
|--------|------------|------|-----|
| Attacker writes a fake `vault.v1.bin` the operator accidentally loads | File rejected on passphrase mismatch (Argon2id salt differs, GCM tag invalid) | `internal/creds/vault.go:Unlock` | ADR-018 |
| Impersonation of `vault init` — attacker seeds a vault the operator then populates | `vault init` refuses if file already exists (`ErrFileExists`); operator must explicitly remove | `internal/creds/vault.go:InitToFile` | PITF-021 |
| Spoofed canary webhook caller | HMAC-SHA256 signature in `X-Elsereno-Signature` (receiver verifies) | `internal/canary/canary.go:Send` | — |

## T — Tampering

| Threat | Mitigation | Code |
|--------|------------|------|
| Bit-flip / offline mutation of vault file | AES-256-GCM AEAD: any byte change fails the tag check, `Unlock` returns `ErrBadPassphrase` | `internal/creds/vault.go:Unlock` |
| Audit log row rewrite in DB | JCS hash chain: each row's hash includes `prev_hash`, recomputed + verified by `audit.Verify` | `internal/audit/canonical.go:Verify` |
| Attacker deletes audit rows to hide activity | Purge is tombstone-only; gap detection fires on `Verify`. `compact` inserts `chain_rebase` marker — visible + cannot be forged | `internal/audit/canonical.go`, ADR-013 + ADR-025 |
| Passphrase file replaced by symlink to `/dev/stdin` | `loadPassphraseFile` rejects non-regular files (`os.Lstat` check for mode type) | `cmd/elsereno/cmd_vault.go:loadPassphraseFile` |

## R — Repudiation

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator denies running a destructive command | Every vault + creds verb emits an audit event (`vault_init`, `vault_unlock`, `creds_reveal`, etc.); offensive_{allowed,denied,failed} emitted by `offensive/confirm.Authorize` | `internal/audit/events.go` |
| Disputed chain integrity after incident | `elsereno audit verify` walks the chain; mismatched `entry_hash` returns typed `ErrChainBroken` | `internal/audit/errors.go` |

## I — Information disclosure

| Threat | Mitigation | Code |
|--------|------------|------|
| Passphrase in process memory after unlock | `memguard.LockedBuffer`: master key lives in mlocked region zeroised on SIGINT/SIGTERM + `vault lock` | `internal/creds/vault.go:deriveMaster` |
| Passphrase in shell history / argv / env | `vault init` rejects `--passphrase` CLI value; only stdin prompt or `--vault-passphrase-file <0600 path>`. Env vars accepted only with TTY warning (ADR-026) | `cmd/elsereno/cmd_vault.go` |
| Group/other read on passphrase file | `loadPassphraseFile` rejects any mode `perm &^ 0o600 != 0` | `cmd/elsereno/cmd_vault.go:loadPassphraseFile` |
| Secret substrings in logs (API keys, bearer tokens) | Zerolog redaction hook: specific-pattern match + Shannon entropy >4.5 b/B + UUID exemption | `internal/telemetry/redact.go`, PITF-004 |
| Audit payload with plaintext secret | Audit payload stores `payload_hash` for offensive events, never the raw bytes | ADR-039 |

## D — Denial of service

| Threat | Mitigation | Code |
|--------|------------|------|
| Attacker fills vault with huge entries | Vault is file-backed per `InitToFile`; size check at `Store` (bounds enforced at caller; no explicit quota yet) | — (F8: add `VaultQuota` config) |
| DB fills with spammed audit rows | Append-only design; retention policy (`internal/retention`) purges findings but never audit metadata (`IsProtectedMetadata`) | `internal/audit/events.go:IsProtectedMetadata` |
| Offline brute force on leaked vault file | Argon2id `time=3, memory=64 MiB, threads=4` — ~150 ms / attempt; offline brute force infeasible on strong passphrases | ADR-018 |

## E — Elevation of privilege

| Threat | Mitigation | Code |
|--------|------------|------|
| Vault unlocked by attacker on same machine | Vault zeroised on process exit; re-unlock requires passphrase + file access | `internal/creds/vault.go:Lock` |
| HKDF sub-key leak gives offensive-confirm-token forging | Master key + HKDF sub-keys live only in memguard buffer; ExpectedToken zeroes the derived 32-byte HMAC key on defer | `offensive/confirm/confirm.go:ExpectedToken` |
| Audit writer forged to emit fake "offensive_allowed" rows | Writer is a single sequential INSERT path guarded by the process's DB credentials; cross-process tampering requires DB access, which the audit table's CHECK constraint + chain verification catches | ADR-023 |

## Residual risk (accepted)

- **No HSM/KMS**: all secrets live on disk protected by Argon2id +
  GCM. Acceptable for the single-operator workstation model; vNext
  ticket for HSM integration (`.context/STATE.md` F-future carry-
  over).
- **No tamper-evident hardware**: someone with root on the box can
  read `/proc/<pid>/maps` and potentially dump the memguard region
  between unlock and lock. Operator threat model explicitly
  assumes trusted operator workstation (`.context/security-
  model.md`).
- **No secret rotation scheduler**: operators must run
  `elsereno creds rotate <name>` manually. F8 adds scheduled
  rotation via outbox.
