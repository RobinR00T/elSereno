---
id: 011
title: `atmodem` plugin for AT-over-TCP (Hayes/GSM/EN 81-28)
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-011: `atmodem` plugin for AT-over-TCP (Hayes/GSM/EN 81-28)

## Context
Legacy telephony and GSM modems remain a common exposed surface on ICS
networks, including lift interphones under EN 81-28. These are typically
accessible via Telnet-like AT-over-TCP on a scattered set of ports.

## Decision
Ship a `atmodem` plugin in F2 that:
- Parses AT line/multi-line responses, including `OK / ERROR /
  +CME ERROR / +CMS ERROR / CONNECT / NO CARRIER / RING`.
- Fingerprints Hayes, GSM, vendor-specific strings, and EN 81-28 lift
  signatures.
- Provides read-only operations: `info/config/network/signal/imsi/imei`
  with an audit entry per operation.
- Under `-tags offensive` + `--dial-allowed`, offers `dial`, `sms`,
  `sms-read`, `phonebook-dump`, `at-raw` with triple confirmation.
- Proxy mode blocks destructive commands (`ATD*`, `ATA`, `AT+CMGS`,
  `AT+CMGW`, `AT+CMSS`, `AT+CMGD`, `AT+CFUN`, `AT+CPWROFF`, `+++`).

## Consequences
### Positive
- Covers a legitimate and under-served audit surface.
- Read/write split matches the general offensive build tag discipline.

### Negative / trade-offs
- Dialling introduces legal and cost exposure; mitigated by the hard
  ≤3-digit block, configurable `blocked_numbers`, and triple confirm.
- IMSI/IMEI are personal data (GDPR); only stored in the encrypted vault.

## Alternatives considered
- Skipping AT coverage (rejected: real-world lifts and industrial modems
  are commonly exposed).

## References
- `.context/protocols/atmodem.md`; `LEGAL.md` (GDPR).
