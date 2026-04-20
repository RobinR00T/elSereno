---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 600
---

# Threat model index

Per-surface STRIDE analysis for the critical ElSereno packages.
Treat each file here as the "what can go wrong, and how we stop it"
counterpart to the ADR that declared the *design*.

## STRIDE categories

| Letter | Threat | Mitigation style |
|--------|--------|------------------|
| **S** | Spoofing identities | Auth (Bearer / Basic / cosign), mutual TLS, HMAC on webhooks |
| **T** | Tampering with data | JCS hash chain, wire-layer parsers, signed artefacts, `os.Lstat` permission checks |
| **R** | Repudiation of actions | Tamper-evident audit chain; offensive_{allowed,denied,failed} events |
| **I** | Information disclosure | Redaction hook, `SafeBytes` / `SafeField`, 0600 passphrase files, CSP nonces |
| **D** | Denial of service | Timeouts, circuit breaker, semaphores, rate limiting, evidence truncation |
| **E** | Elevation of privilege | `PR_SET_NO_NEW_PRIVS`, seccomp-bpf (F7+ filters), triple-confirm on writes, `internal/exec` allowlist |

## Files

| Surface | Doc | Leading mitigation |
|---------|-----|--------------------|
| Vault + audit chain | [vault-audit.md](vault-audit.md) | AES-GCM + Argon2id + JCS hash chain |
| Web server + API + dashboard | [web.md](web.md) | CSRF (HKDF from vault) + Cookie Secure + CSP nonces |
| Scanner + proxy framework | [scanner-proxy.md](scanner-proxy.md) | Wire-layer write-ban + per-host semaphore + temporal dedupe |
| Subprocess + scope | [exec-scope.md](exec-scope.md) | `SafeCommand` path allowlist + scope ranges + CIDR match |
| Offensive surface | [offensive.md](offensive.md) | ADR-039 triple-confirm + ADR-041 dial guard + seccomp-bpf |
| Observability + canary | [telemetry-canary.md](telemetry-canary.md) | Redaction hook + HMAC-SHA256 on canary webhook |

## Residual risk acceptance

Every document ends with a "Residual risk" section listing threats
we accept because:
- The mitigation cost exceeds the exposure (documented reasoning).
- The threat is out-of-scope (vNext: Windows, multi-user OIDC).
- A compensating control elsewhere addresses it.

Tag closes to 1.0 require **every residual risk** to be referenced
in an ADR or a GitHub issue. A missing reference blocks the
release workflow (see `RELEASING.md` pre-release checklist + F8
compliance automation).

## Updating this tree

When landing a new feature:
1. Locate the surface doc it belongs to.
2. Add a STRIDE row for the new risk OR strengthen an existing row.
3. Link the ADR and the code paths (internal/<pkg>/<file>.go).
4. Include the change in the phase snapshot under `.context/snapshots/`.

When a new surface is added (a new `internal/` or `offensive/`
package with its own attack surface), create a new file in this
directory following `offensive.md`'s layout.
