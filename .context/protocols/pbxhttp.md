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
console UIs that PBX systems expose. Speaks HTTPS only, on its
default port 443 (admin UIs also listen on 80, 8088, 5001, 8443,
411; a plain-HTTP port gets no finding, and another HTTPS port needs
`fingerprint probe`). Vendor detection covers the 14 brands in
`pbxhttp/vendor.go` (FreePBX, PBXact, 3CX, Yeastar, Cisco UCM, Avaya,
Mitel, Grandstream, Fanvil, Yealink, Asterisk, Switchvox, Elastix,
FreeSWITCH). Offensive
write plugin gates per-(method, path) since v1.12.

## Wire format
HTTPS. The `pbxhttp` plugin sends ONE `GET /` with a generic
User-Agent (no HEAD, no other paths).

## Fingerprint strategy
Classify the single response by the substring matchers in
`vendor.go` over the HTML body and the response headers. No
custom header (such as `X-3CX-Phone-System`) or TLS certificate
field is read.

## Read operations (default build)
- `probe`: one HTTPS GET `/`, vendor classification.

## Write / dial operations (offensive build tag)
v1.4+ landed full `offensive/write/pbxhttp/gatedproxy.go`:
- per-(method, path) allowlist. Gates GET / POST against an
  exact path tuple (e.g.,
  `(GET, /admin/config.php)` only, not the whole
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
CVE-2023-29059, Mitel MiCollab CVE-2024-41713, web admin
UIs are a direct RCE path into call infrastructure)}.

## Sentinel cases
- HTML containing FreePBX / Asterisk / 3CX / Mitel: pbx-likely.
- 401 with PBX-realm: pbx-likely.
- Plain HTTP banner: non-pbx-http.
- Silent: no usable reply.
