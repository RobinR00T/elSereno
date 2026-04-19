---
phase: FN
status: draft | implemented | stable | deprecated
last-updated: YYYY-MM-DD
token-budget: 1500
protocol-name: <name>
default-port: <port>/<tcp|udp>
---

# <Protocol Name>

## TL;DR
<3–5 lines>

## Spec references
- Primary: <RFC / standard>
- Secondary: <papers, vendor docs>

## Wire format (summary)
<fields, endian, lengths, quirks>

## Fingerprint strategy
<what we send, what we expect, what we extract>

## Read operations (default build)
- `...`

## Write / dial operations (offensive build tag)
- `...` (risk level)

## REPL commands
- `...`

## Proxy hooks
<what we intercept, log, what read-only mode blocks>

## Known quirks / vendor deltas
- ...

## Test vectors
- `testdata/<name>/benign/...`
- `testdata/<name>/malicious/...` (CVE if any)

## Scoring contribution
<how this protocol affects score factors>

## Open questions
- ...
