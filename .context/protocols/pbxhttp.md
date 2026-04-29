---
phase: F3
status: implemented
last-updated: 2026-04-29
token-budget: 700
protocol-name: pbxhttp
default-port: 443, 80, 8088, 5001, 8443, 411
---

# PBX HTTP

## TL;DR
ElSereno's `pbxhttp` plugin probes the HTTP admin / SIP-
console UIs that PBX systems expose. Targets the port matrix
443 (HTTPS), 80, 8088 (Asterisk ARI), 5001 (3CX), 8443
(FreePBX HTTPS), 411 (Mitel). Vendor detection runs against
~12 PBX-specific HTML / header patterns (Asterisk Manager,
FreePBX, 3CX, Mitel, Avaya, RingCentral, etc.). Offensive
write plugin gates per-(method, path) since v1.12.

## Wire format
Plain HTTP/1.1 (and HTTPS). The `pbxhttp` plugin sends:
- GET `/` with a generic User-Agent.
- HEAD `/admin/` (FreePBX), `/manager/` (Asterisk Manager
  Web), `/api/` (3CX), `/swagger.json` (FreeSWITCH ARI).

## Fingerprint strategy
Multi-path probe (parallel across the path candidates) and
classify by:
- HTML body containing "FreePBX" / "Asterisk" / "3CX" / etc.
- HTTP `Server:` header naming a PBX vendor.
- 401 realm string (e.g., "Asterisk REST Interface").
- Response signature (e.g., 3CX returns `X-3CX-Phone-System`).

## Read operations (default build)
- `probe`: parallel HTTP probes across the path candidates,
  vendor classification.

## Write / dial operations (offensive build tag)
v1.4+ landed full `offensive/write/pbxhttp/gatedproxy.go`:
- per-(method, path) allowlist. Gates GET / POST against an
  exact path tuple (e.g.,
  `(GET, /admin/config.php)` only — not the whole
  `/admin/*` tree).
- v1.17 chunk-3: token-generation cookie (separator 0xFC).

Refusal idiom: HTTP/1.1 405 Method Not Allowed (for refused
methods) or HTTP/1.1 403 Forbidden (for refused paths).

## REPL commands (planned)
- See the generic REPL framework.

## Proxy hooks
Default-build proxy: in-band HTTP request decode. Read-class
methods (GET, HEAD, OPTIONS) forward to upstream; write-class
(POST, PUT, DELETE, PATCH) hit 405 / 403.

## Scoring contribution
factors{protocol_risk:30→70 on pbx-likely, exposure:70,
auth_state:60, capability:30→50 on pbx-likely, impact_class:
40→75 on pbx-likely, **cve_exposure:11** (FreePBX RCE family
CVE-2014-7235 admin shell injection + CVE-2019-19006 +
CVE-2020-25822, Asterisk Manager web CVE-2017-9358, 3CX
CVE-2023-29059, Mitel MiCollab CVE-2024-41713 — web admin
UIs are a direct RCE path into call infrastructure)}.

## Sentinel cases
- HTML containing FreePBX / Asterisk / 3CX / Mitel: pbx-likely.
- 401 with PBX-realm: pbx-likely.
- Plain HTTP banner: non-pbx-http.
- Silent: no usable reply.
