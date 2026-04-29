---
phase: v1.22
status: implemented
last-updated: 2026-04-29
token-budget: 700
protocol-name: redlion
default-port: 789/tcp
---

# Red Lion Crimson / RLN

## TL;DR
ElSereno's `redlion` plugin connects to TCP/789, reads any
unsolicited banner, falls back to a 3-byte zero hello, and
classifies the response by canonical Red Lion / Crimson /
Sixnet banner substring.

## Spec references
- ICS-CERT ICSA-21-103-01, ICSA-22-088-01.
- Shodan banner aggregations.
- Red Lion Crimson 3 product manuals (registration required).

## Wire format
Banner-only fingerprint. RLN frames use a 3-byte handshake +
tag-length-value bodies; we don't parse those.

## Fingerprint strategy
Two-step probe:
1. Read up to 1024 bytes for IOTimeout/2 (unsolicited banner).
2. If no positive ID, send 3-byte zero hello, read again.

Substring matches: 12 canonical strings ordered most-specific
first (Red Lion Controls > Red Lion, Crimson 3 > Crimson 2,
etc.) so the matched substring in the finding note is
informative.

## Read operations (default build)
- `probe`: dial → read → fallback 3-byte hello → classify.

## Write / dial operations (offensive build tag)
Deferred. Crimson 3 supports tag manipulation, project
download, password reset, remote firmware upgrade.

## Proxy hooks
Fail-closed. RLN TLV stack not implemented in chunk 3.

## Scoring contribution
factors{protocol_risk:75, exposure:75, auth_state:85, capability:30
(70 on Red Lion reply), impact_class:70, cve_exposure:5}.
- protocol_risk 75 (vs 80 PLCs) — HMI/RTU rather than direct PLC.
- impact_class 70 — HMI screen forge + tag forcing + firmware push.
- cve_exposure 5 — ICSA-21-103-01 (hardcoded crypto key) +
  ICSA-22-088-01 (path traversal); smaller than CoDeSys's 10
  but non-zero.

## Sentinel errors (wire package)
- ErrShortFrame: < 4-byte response.
- ErrNotRedLion: response carries no canonical banner substring.
