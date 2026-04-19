---
phase: F2
status: closed
date: 2026-04-19
token-budget: 1200
---

# Phase F2 snapshot — Legacy telephony (XOT + AT modems)

**Closed on 2026-04-19.** `make ci` green end-to-end. Repo is now at
the brief's F2 milestone: ready to push to a private GitHub
repository (the operator performs the push manually per the brief's
section 17 paso 17).

## Shipped

### XOT (X.25 over TCP, RFC 1613)
- `internal/protocols/xot/wire/`: from-scratch parser.
  - `header.go`: RFC 1613 envelope (Version=0x0000, big-endian
    Length), with max-4096 ceiling and min-3 floor
    (ErrBadVersion / ErrPayloadTooLong / ErrPayloadTooShort).
  - `x25.go`: PTI classification (Call/Clear/RR/RNR/REJ/Interrupt/
    Reset/Restart/Diagnostic/Data). `MarshalCallRequest` builds a
    minimal probe frame; `ReadXOTFrame`/`WriteXOTFrame` round-trip.
  - Fuzz targets: FuzzParseHeader, FuzzParseX25, FuzzFrameRoundTrip
    (seeded with canonical legal frames + adversarial bytes).
- `internal/protocols/xot/xot.go`: Plugin implementing core.Protocol.
  Sends a Call Request (LCN=1, no addresses, no facilities),
  classifies the first response, scores per ADR-006. Silent close
  emits info-level findings; Call Accepted lifts the capability
  factor; Clear Indication records cause + diag.
- `simulators/xot/`: Go simulator with `--response=clear|accept|
  restart|silence` and `--cause/--diag` knobs so tests can drive
  every classification path deterministically.
- `.context/decisions/027-xot-plugin.md` + `.context/protocols/xot.md`.

### AT modem (Hayes / GSM / EN 81-28)
- `internal/protocols/atmodem/wire/`:
  - `parse.go`: response state machine recognising OK / ERROR /
    CONNECT / NO CARRIER / NO DIALTONE / BUSY / NO ANSWER / RING /
    +CME ERROR / +CMS ERROR with numeric code extraction, a
    64 KiB response ceiling (ErrTooLong), and CR/LF tolerance.
  - `fingerprint.go`: vendor detection table. `Detect(banner, cgmi)`
    classifies into Hayes / GSM / EN 81-28 (lift) with vendor hints
    (Siemens, Nokia, Sierra, MultiTech, Cinterion, Telit, u-blox,
    Quectel, Huawei, KONE, Otis, Schindler).
  - Fuzz targets: FuzzParseResponse, FuzzDetect.
- `internal/protocols/atmodem/atmodem.go`: Plugin implementing
  core.Protocol. Probe sequence: drain banner 100 ms → `AT` →
  `ATI` → `AT+CGMI`. Read-only by construction. Scoring: GSM raises
  protocol_risk + impact_class (SMS/IMSI surface); EN 81-28 pushes
  impact_class to 90 (lift-alarm path).
- `ForbiddenPrefixes` is the source-of-truth write-ban list:
  `ATD*`, `ATA`, `AT+CMGS`, `AT+CMGW`, `AT+CMSS`, `AT+CMGD`,
  `AT+CFUN`, `AT+CPWROFF`, `+++`. The proxy handler drops any
  matching line (case-insensitive, whitespace-tolerant); the
  simulator refuses them too so test scripts can't accidentally
  "dial".
- `simulators/atmodem/`: Go simulator with `--vendor=siemens|nokia|
  kone|generic` and `--banner` personas.
- `.context/decisions/028-atmodem-plugin.md` + `.context/protocols/
  atmodem.md`.

### Plugin registration
- `cmd/elsereno/plugins.go`: banner + xot + atmodem. `elsereno
  plugins list` reports all three in the default build.

### Testdata
- `testdata/atmodem/benign/` (ok, siemens-ati, kone-banner, cme-error).
- XOT test vectors are constructed in code via
  `wire.MarshalCallRequest` to avoid checking fragile binary files
  into the repo.

## Non-trivial decisions made

- **REPL bindings deferred**: both plugins declare REPL but return a
  "wired in F4" error. The generic REPL framework (with history,
  tab-completion, audit logging) is a cross-cutting concern shared
  with the 9 F4 plugins; binding each one up-front inside F2 would
  double the surface without covering the real work.
- **Offensive stays out of F2**: dial / SMS / phonebook-dump /
  at-raw are F5 items per the brief. The default-build proxy still
  blocks them today so a field deployment can't be coerced into
  dialling through ElSereno even via the proxy.
- **AT response parser uses `bufio.Scanner` with a 64 KiB cap**. Real
  modems rarely emit more than a few KiB; the cap mitigates memory
  exhaustion against adversarial responses.
- **Vendor detection via a priority table** (`vendorMatches`)
  replaces a 12-case switch to stay under golangci-lint's gocyclo
  ceiling — and keeps the ordering explicit (lifts before GSM vendors
  because lift stacks sometimes advertise GSM radios).

## New pitfalls captured

None. The work surfaced the usual gosec/gocyclo friction around
hash helpers (port-to-bytes splits) and exhaustive switches; fixed
inline with rationale comments.

## Debt accepted (moved to F3+)

- **XOT REPL** (`call / clear / data / quit`) — generic REPL
  framework lands in F4.
- **AT REPL** (`atinfo / signal / imsi / imei / operator / quit`)
  — same.
- **Proxy framework instrumentation**: the two protocol proxies
  exist but run without per-frame logging / hook points. The F3
  framework binds those in.
- **XOT X.29 PAD parameter handling** — needed for full Call
  Accepted interaction; F3+.
- **Offensive plugins** (write/dial/sms/harvest) — F5.

## What moves to F3

- Proxy framework under `internal/proxy/` with hook registration,
  per-frame logging, and the Modbus read-only plugin.
- Chaos-testing helpers under `test/chaos/`.
- Integration against pymodbus simulator.

## Closure status

The brief's F2 criterion is "hito: repo empujable a GitHub privado".
All code is committed, `make ci` is green end-to-end, and
`.context/STATE.md` is updated. The operator performs the push:

```
git remote add origin git@github.com:<owner>/elsereno.git
git push -u origin main
```
