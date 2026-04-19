---
phase: F4
status: closed
date: 2026-04-19
token-budget: 1500
---

# Phase F4 snapshot — Remaining ICS plugins + dashboard + API

**Closed on 2026-04-19.** `make ci` green end-to-end. The plugin set
covers every protocol the brief calls out for v1; the web dashboard
has a working overview page + a read-only JSON API with an OpenAPI
3.1 spec.

## Shipped

### Eight new protocol plugins
All ship with a from-scratch wire parser under
`internal/protocols/<name>/wire/`, a probe + fingerprint Plugin, a
fuzz target, basic tests, a protocol doc, and an ADR.

| Plugin | Port | Approach |
|---|---|---|
| `s7` | 102/tcp | TPKT (RFC 1006) + COTP Connection Request; classify CC reply |
| `enip` | 44818/tcp | Encapsulation Protocol (ODVA CIP Vol 2) ListIdentity; parse Identity object |
| `bacnet` | 47808/udp | BVLC header + Who-Is; detect I-Am reply |
| `dnp3` | 20000/tcp | Data-link frame 0x05 0x64 + minimal Read Class 0 |
| `iec104` | 2404/tcp | APCI header + TESTFR act; classify U/S frames |
| `hartip` | 5094/tcp | HART-IP header + session initiate |
| `fox` | 1911,4911/tcp | Niagara Fox banner scrape for "fox.version=" |
| `atg` | 10001/tcp | Veeder-Root I20100 command + response match |

### banner vendor dictionary
`internal/protocols/banner/vendors.go` adds a `DetectVendor(banner)`
helper with a priority-ordered rule table. Covers Moxa NPort,
Lantronix, Digi (PortServer + Digi Connect), NetBurner, KONE/Otis/
Schindler lifts, OpenSSH. Runs on the banner strings the existing
banner plugin already SafeBytes-sanitises.

### Plugin registration
All 12 default-build plugins register in
`cmd/elsereno/plugins.go`. `elsereno plugins list`:

```
atg banner bacnet dnp3 enip fox hartip iec104 modbus s7 xot
```
plus `atmodem`. 12 total.

### Dashboard + API + OpenAPI
- `internal/web/handlers/dashboard.go`: overview page listing
  registered plugins with build-tag badges. Static HTML + inline
  CSS (ADR-007 — no Node at build). The polished HTMX dashboard
  lands in F4 chunk 2.
- `internal/web/handlers/api.go`: `/api/v1/plugins`,
  `/api/v1/scoring`, `/api/v1/health`. All read-only. Envelope
  shape: `{schema: "api:v1", data: {...}}` so downstream tools can
  contract-version without guessing.
- `internal/web/server.go` now mounts `/api/v1/` and `/`.
- `docs/openapi.yaml`: OpenAPI 3.1 spec covering `/healthz`,
  `/readyz`, and the three `/api/v1/*` endpoints.

### Conpot in the integration suite
`simulators/docker-compose.test.yml` now spawns a Conpot
(`honeynet/conpot:latest`) container that emulates Modbus, S7,
EtherNet/IP, BACnet, HART-IP, IEC-104, Niagara Fox, and Veeder-Root
ATG. Port-mapped to avoid collisions with the operator's dev
services:

| Mapped | Upstream | Protocol |
|---|---|---|
| 1502 | 502 | modbus |
| 10002 | 102 | s7 |
| 44819 | 44818 | enip |
| 47809/udp | 47808/udp | bacnet |
| 50794 | 5094 | hartip |
| 60870 | 2404 | iec104 |
| 11911 | 1911 | fox |
| 20001 | 10001 | atg |

Operators run `docker compose -f simulators/docker-compose.test.yml
up -d` and then hit every protocol with a single `elsereno scan`
against the list.

### ADRs + protocol docs
- `.context/decisions/031..038` cover the eight new plugins,
  following the ADR-027/ADR-028 template.
- `.context/protocols/{s7,enip,bacnet,dnp3,iec104,hartip,fox,atg}.md`
  updated from F0 placeholders to `status: implemented` with the
  real spec references and per-plugin fingerprint strategy.

## Non-trivial decisions made

- **Minimal viable parsers**. Each wire parser recognises the header
  + the subset of body fields the probe actually uses, not the full
  protocol semantics. This is deliberate: the scan use case only
  needs "can I classify this target?", not "can I drive a complete
  session?". Full semantics land per-plugin when REPL / offensive
  arrive.
- **Pass-through proxies** for the new plugins. The write-gating
  matrix (per-FC / per-service / per-subcode) is protocol-specific
  and F5-scoped (each write has its own triple-confirm semantics).
  Only Modbus and AT-modem ship with active gating today — the
  other proxies are F3-framework scaffolds.
- **Conpot over per-plugin simulators**. Writing nine simulators
  duplicated the work the Conpot project already does. The Go
  simulators stay for protocols where deterministic in-CI behaviour
  matters (banner, XOT, atmodem, modbus); everything else uses
  Conpot for broader coverage.
- **Inline HTML over embed.FS**. The F4 chunk-2 polish moves the
  dashboard into `templates/` with per-page files + HTMX swaps.
  Today's MVP is one template so the scaffold stays readable.

## New pitfalls captured

None. Lint surfaced the usual exhaustive / revive / misspell noise
around CSS `color` — fixed inline.

## Debt accepted (moved to F4 chunk 2 or F5)

- **Generic REPL framework**. All twelve plugins declare a REPL
  method but return "wired in F4 chunk 2". Read-only commands land
  with the REPL framework; writes are F5.
- **Findings / runs / targets API endpoints**. The three that need
  DB rows wait for the audit writer and the findings sink. The
  scaffold is in `handlers/api.go` so adding them is a single
  router line each.
- **TUI (bubbletea)**. Cleanly scoped to its own chunk; the
  dashboard MVP lets operators use the browser today.
- **Per-plugin proxy write-gating** for S7, ENIP, BACnet, DNP3,
  IEC-104, HART-IP, Fox, ATG. F5 adds the tables + triple-confirm
  wrappers.
- **CSRF-backed auth on `/api/v1/*`**. The endpoints are read-only
  today; Bearer-token middleware lands when write endpoints do.

## What moves to F5

- Offensive build (`-tags offensive`): writes, exploits, credential
  harvesting, dial.
- Per-protocol write-gating matrices (the seven pending in F4).
- seccomp-bpf sandbox for offensive subprocesses on Linux
  (ADR-010's deferred choice).
- `--no-allowlist` bypass with audit trail.
- canary scope.yaml webhook.
- Generic REPL framework under `internal/repl/` with history,
  tab-completion, and per-protocol command registration.
