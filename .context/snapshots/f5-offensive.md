---
phase: F5
status: closed
last-updated: 2026-04-19
token-budget: 1500
---

# Snapshot — F5: Offensive build

Closed **2026-04-19**. All safety-critical deliverables shipped
behind `-tags offensive` + the triple-confirm wrapper. No offensive
code path is reachable from the default build.

## Decisions
- **ADR-039** — triple-confirm wrapper (build tag + `--accept-writes`
  + `--confirm-target` + HMAC-SHA256 token derived from vault via
  HKDF `info="elsereno/offensive/confirm/v1"`). Every Authorize call
  emits one of `offensive_allowed` / `offensive_denied` /
  `offensive_failed` to the audit chain with the payload hash but
  never the payload.
- **ADR-040** — per-plugin proxy write-gating matrix for the 7 F4
  pass-through plugins. Every TCP-based plugin now refuses non-read
  frames at the wire layer with a protocol-native refusal response.
- **ADR-041** — dial guard. Unbypassable ≤3-digit hard block + scope
  `blocked_numbers` list + confirm-wrapper. Wardialing batch stays
  vNext.
- **ADR-042** — Linux seccomp-bpf sandbox via pure Go
  `golang.org/x/sys/unix.Prctl`. F5 installs `PR_SET_NO_NEW_PRIVS`
  unconditionally; BPF-filter instruction sequences are deferred to
  F6 (the filters are profile-scoped and land with the subprocess
  integrations).

## Packages landed

### `offensive/confirm`
Authorize + ExpectedToken + KeyDeriver + Auditor interfaces. 9 unit
tests including constant-time comparison, audit-write failure
blocking the allowed path, and distinct-master-key token
divergence.

### `offensive/write/{modbus, s7, enip, bacnet}`
Pure `Build` + `MutationFor` + (modbus only, for now) `Execute`.
Each plugin emits a deterministic SHA-256 payload hash so the
operator's dry-run token exactly matches the real-run token.
- modbus: FC 5/6/15/16.
- s7    : WriteVar / PLC Stop / PLC Restart.
- enip  : Set Attribute Single / Reset Identity.
- bacnet: WriteProperty (UDP BVLC datagram).

### `offensive/dial`
`Validate(number, scope)` with three gates in order: normalise →
hard ≤3-digit refusal (unbypassable) → scope blocked-numbers.
Triple-confirm runs separately after Validate returns ok.

### `offensive/harvest`
Prober interface + 4 protocol implementations:
- `telnet` with IAC option-negotiation refusal and login-state
  machine.
- `ftp` with RFC 959 multi-line response parsing.
- `http-basic` via net/http after verifying a
  `WWW-Authenticate: Basic` challenge.
- `snmp` SNMPv2c GetRequest for sysDescr.0 with a hand-crafted
  ASN.1-BER encoder / decoder.
`DefaultCredentials()` ships a small ICS default-password list;
operators widen via `--creds-file` (CLI lands in F6).

### `offensive/sandbox`
Profile enum (Exploit / Harvest / Dial); Linux Load() installs
PR_SET_NO_NEW_PRIVS; non-Linux degrades gracefully with
Availability.Kind=unavailable. Tests cover bad profile,
valid profile, and degraded-continuation contracts.

### `offensive/exploits`
Registry + Module interface + 2 CVE implementations:
- **CVE-2015-5374** — Siemens SIPROTEC 4 / Compact EN100 UDP/50000
  DoS.
- **CVE-2019-10953** — Schneider / Allen-Bradley / Phoenix Contact
  CIP ListIdentity DoS with inflated encapsulation length.
Both are strictly DoS; no memory-corruption primitives ship.

### `internal/canary`
Sender interface + HTTP implementation + InMemorySender for tests.
POSTs `canary:v1` JSON envelopes to scope.yaml.canary.alert_webhook
with optional HMAC-SHA256 signature in X-Elsereno-Signature.

### `internal/scope.CheckDial`
Walks `Dial.BlockedNumbers` (exact or prefix match) for the gate-2
portion of ADR-041.

### `internal/exec.CommandSpec.AllowAnyPath + BypassAuditor`
`--no-allowlist` escape hatch. Requires a BypassAuditor; failure to
audit aborts the spawn. Default reason "unspecified" when empty.

## Per-plugin proxy write-gating

| Plugin  | Category classifier                         | Refusal frame                                  |
|---------|---------------------------------------------|------------------------------------------------|
| s7      | `FuncCommSetup/ReadVar` → Read; others Write | S7 AckData errClass 0x85 / errCode 0x01       |
| enip    | List*/Register/Unregister → Read; SendRRData / SendUnitData Write | Encapsulation status 0x0001 |
| dnp3    | PRM=1 FC 1/9 Read; FC 0/3/4 Write           | Secondary FC 15 "Not Supported"                |
| iec104  | S/U frames Read; I frames Write             | STOPDT_act (Control 0x13)                      |
| hartip  | SessionInitiate/Close/KeepAlive Read; TokenPassPDU Write | Session-close, status 0x04         |
| atg     | `I`-family commands Read; everything else Write | Veeder-Root `9999FF1B` Data Error          |
| fox     | (line-oriented admin) — default fail-closed | "fox a 0 -1 fox denied\n" + disconnect         |
| bacnet  | (UDP — incompatible with TCP proxy framework) | immediate error from Handle                  |

## Notable engineering choices
- Vault-derived token means an operator cannot script past the
  triple confirm without unlocking the vault first.
- Wire-layer write-ban in every TCP-based plugin means a bug in the
  CLI layer cannot widen the default build's posture.
- Exploit harness returns authorised payload bytes (not the
  delivered I/O result) so the audit chain captures the decision
  and the payload hash, keeping the delivery plane smaller.
- Sandbox degrades gracefully on macOS (log + continue) rather than
  refusing to run — matches F0 developer workflow.

## Metrics
- 8 commits on main (chunks 1–8).
- ~3100 LOC added behind `-tags offensive`.
- 52 new unit tests (all offensive-tag).
- `make ci` green on both default and offensive build variants.

## Carry-overs to F6
- CLI verbs `elsereno write|exploit|harvest|dial` — wiring lands
  when the DB-backed audit writer ships.
- seccomp-bpf BPF-filter instruction sequences (profile shell
  already in place).
- Per-plugin offensive writes (`-tags offensive` WriteGatedHandler)
  substitute the default refusal handler with a confirm-routed
  forwarder.
