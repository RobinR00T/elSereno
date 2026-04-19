---
id: 028
title: atmodem plugin — Hayes / GSM / EN 81-28, read-only default
status: accepted
date: 2026-04-19
phase: F2
---

# ADR-028: atmodem plugin — Hayes / GSM / EN 81-28, read-only default

## Context
AT-over-TCP modems are pervasive in OT: serial-to-IP gateways, lift
interphones (EN 81-28), remote telemetry on legacy pumps / ATGs, and
GSM bridges on ICS maintenance lines. Exposure is high-risk because
the write side of the AT command set can make real phone calls, send
SMS, disable the radio, dump the phonebook, and surface IMSI/IMEI —
all with legal, physical, and GDPR consequences.

The brief scopes dial / SMS / phonebook-dump / at-raw to the offensive
build tag (`-tags offensive`) with `--dial-allowed` and a triple
confirm (section 7 F2b + F5). The default build must be strictly
read-only.

## Decision
- Ship a wire parser under `internal/protocols/atmodem/wire/` that
  recognises the canonical terminal codes
  (OK / ERROR / CONNECT / NO CARRIER / NO DIALTONE / BUSY / NO ANSWER
  / RING / +CME ERROR / +CMS ERROR) and is fuzz-tested.
- Ship a fingerprint detector that classifies responses into
  `hayes` / `gsm` / `en81-28` (lift) with vendor hints for Siemens,
  Nokia, Sierra, MultiTech, Cinterion, Telit, u-blox, Quectel,
  Huawei, KONE, Otis, Schindler.
- Probe sequence: `AT` → `ATI` → `AT+CGMI`. Any `AT` response other
  than OK emits an info-level finding.
- The proxy handler inspects each client→upstream line and swallows
  anything whose prefix matches the forbidden list:
  `ATD*`, `ATA`, `AT+CMGS`, `AT+CMGW`, `AT+CMSS`, `AT+CMGD`,
  `AT+CFUN`, `AT+CPWROFF`, and the `+++` escape sequence.
  Matching is case-insensitive and tolerates leading whitespace.
- The REPL binding lands in F4 (generic REPL). Even there, the
  default build refuses writes.
- Offensive operations (`dial`, `sms`, `sms-read`,
  `phonebook-dump`, `at-raw`) land in F5 behind `-tags offensive`
  with `--dial-allowed` and triple confirm; numbers ≤ 3 digits are
  blocked hard (LEGAL.md); additional blacklists come from
  `scope.yaml`.
- A companion Go simulator at `simulators/atmodem/` lets the
  integration suite exercise the plugin end-to-end without a real
  modem. The simulator itself also refuses the forbidden prefixes
  so test scripts cannot accidentally dial.

## Consequences
### Positive
- Zero external dependencies for the parser; stdlib `bufio` + a
  hand-written scanner split handle CR/LF quirks cleanly.
- EN 81-28 lift detection is distinct from GSM; the scoring model
  raises `impact_class` sharply for lifts because disrupting an
  alarm path endangers lives.
- The proxy write-ban is a single source of truth (`ForbiddenPrefixes`);
  tests and the simulator reference the same list.

### Negative / trade-offs
- Some legacy Hayes modems echo the command before replying;
  ReadResponse treats the echo as a normal payload line, which is
  fine for fingerprinting but introduces noise in the payload slice.
  Callers that care clean it up.
- The `AT+CGMI` probe is GSM-specific; pure Hayes modems respond
  ERROR, which still lets us fingerprint via ATI alone.

## Alternatives considered
- **Third-party AT libraries** (several Go wrappers exist): all are
  either archived, bound to a specific vendor (Sierra, u-blox), or
  unnecessarily wide-scoped; PITF-011 applies.
- **Parsing only OK/ERROR**: loses the CONNECT / NO CARRIER / RING
  distinctions that `scan` + `explain` need.

## References
- 3GPP TS 27.005 / 27.007 — GSM AT command set.
- Hayes Standard AT Command Set (1981).
- EN 81-28:2018 — Remote alarm on passenger and goods passenger lifts.
- `.context/protocols/atmodem.md` — operator-facing notes.
- LEGAL.md — GDPR considerations for IMSI/IMEI/phonebook data.
