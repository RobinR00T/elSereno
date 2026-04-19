---
id: 041
title: Dial guard — ≤3-digit hard block + scope.blocked_numbers
status: accepted
date: 2026-04-19
phase: F5
---

# ADR-041: Dial guard — ≤3-digit hard block + scope.blocked_numbers

## Context
F5 introduces `elsereno dial` (offensive build only) which places
outgoing PSTN calls over AT-attached modems or SIP gateways. Dial
misuse has catastrophic legal blast radius: a short-digit dial
(`112`, `999`, `911`, `062`) hits emergency services; regulated
premium numbers rack up cost within seconds; and any dial that
leaves an uncontrolled infrastructure is potentially a wiretap
or harassment event.

## Decision
Two independent gates, enforced in this order inside
`offensive/dial.Validate(number, scope, cfg)`:

### Gate 1 — hard-coded ≤3-digit block
After normalisation (strip spaces, dashes, country codes, leading
`+` / `00`, discard non-digits), if the remaining digit count is ≤ 3,
the call is **refused unconditionally**. This cannot be bypassed by
configuration, CLI flag, vault state, or build tag. The refusal
bubbles out as `ErrShortNumber` and audits as `dial_denied_short`.

### Gate 2 — scope.yaml `blocked_numbers`
`scope.yaml` gains an optional `blocked_numbers` list (E.164 strings
or regex prefixes like `^0090`). The normalised number is matched
against every entry; any match refuses with `ErrBlockedByScope` and
audits as `dial_denied_scope`.

### Gate 3 — triple-confirm wrapper (ADR-039)
The remaining dials still pass through `offensive/confirm.Authorize`
with `CategoryDial`; `ConfirmTarget` is the normalised number and the
token is derived from `HMAC(masterKey, "dial" || 0x00 || norm_number)`.

### Wardialing
Batch dial (sweeping a range) is explicitly **vNext**. F5 supports
only individual dial with `--number <E.164>`. `scope.yaml` remains
the authority; no CLI flag widens it.

## Consequences

### Positive
- Gate 1 is unbypassable short of editing and recompiling the source
  — the exact posture this class of risk warrants.
- Gate 2 is operator-visible in `scope.yaml` and survives config
  reload without a binary rebuild, so operators in different legal
  jurisdictions can maintain appropriate blocklists.
- Confused-deputy attacks (CLI wrapper passes a short number through
  a later-stage tool) fail closed at Gate 1.

### Negative / trade-offs
- Test fixtures that want to verify dialer plumbing without actually
  placing a call must use numbers ≥ 4 digits (easy).
- A loopback-only test harness with mock modem can be argued for a
  softer Gate 1 in tests; rejected — we use a mock at the transport
  layer, not a mocked `Validate`, so the real guard stays in the
  call path.

## Alternatives considered
- **Single "blocklist" config**: rejected. The static list is the
  part we CANNOT let anyone edit out.
- **Prefix-based hard-coded list (112, 911, 999, 062, etc.)**: more
  surgical, but any short prefix is a red flag and we genuinely do
  not need ≤3-digit dial for any legitimate offensive scenario.

## References
- ADR-039 (triple-confirm).
- `offensive/dial/validate.go`.
- `.context/protocols/atmodem.md` (dial command surface blocked at
  the AT-proxy wire layer already).
- PITF-016, PITF-032 (secret handling for SIP/modem creds).
