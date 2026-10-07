---
phase: F3
status: implemented
last-updated: 2026-04-29
token-budget: 800
protocol-name: sip
default-port: 5060/udp+tcp
---

# SIP

## TL;DR
ElSereno's `sip` plugin sends an OPTIONS request to UDP/5060 (UDP
only: no TCP probe, no fallback) and classifies the response by
Status-Line + `Server:` / `User-Agent:` headers. Vendor detection
covers the 15 brands in `sip/vendor.go` (Asterisk, FreePBX, 3CX,
Cisco UCM, Cisco SIP gateway, Mitel, Avaya, Yeastar, Grandstream,
Fanvil, Yealink, Kamailio, OpenSIPS, FreeSWITCH, SER). Offensive
write plugin gates per-method, INVITE prefix, REGISTER AOR,
From-domain since v1.12.

## Spec references
- RFC 3261 (SIP, Session Initiation Protocol).
- RFC 3327 / RFC 3581 / RFC 4566 (extensions).
- RFC 4475 (SIP torture tests, used for fuzz-corpus seeds).

## Wire format
Text-based request-response (HTTP-like). Default port 5060
(plain), 5061 (TLS). UDP and TCP both exist on 5060; this plugin
probes UDP only.

OPTIONS request (probe):
```
OPTIONS sip:<target host:port> SIP/2.0
Via: SIP/2.0/UDP <target host:port>;branch=z9hG4bK<random>
From: <sip:<target host:port>>;tag=<random>
To: <sip:<target host:port>>
Call-ID: <random>@<localhost>
CSeq: 1 OPTIONS
Max-Forwards: 70
Content-Length: 0
```

## Fingerprint strategy
OPTIONS request with random `Via:` branch + `From:` tag +
`Call-ID`. Uses the Status-Line and the Server / User-Agent
headers (Allow and Supported are not parsed). Any SIP status line
yields a scored finding.

Vendor classification: the priority-ordered substring matchers in
`sip/vendor.go` over Server and User-Agent, for the 15 brands above.

## Read operations (default build)
- `probe`: OPTIONS over UDP (no TCP, no fallback).

## Write / dial operations (offensive build tag)
v1.4+ landed full `offensive/write/sip/gatedproxy.go`:
- per-method allowlist (INVITE, REGISTER, MESSAGE, SUBSCRIBE,
  NOTIFY, PUBLISH, REFER, INFO, UPDATE, OPTIONS, CANCEL, ACK,
  BYE).
- v1.9 chunk: per-INVITE-prefix allowlist (gates To: URI
  prefix to defeat toll-fraud number patterns like
  `sip:0011...@target`).
- v1.10 chunk: per-REGISTER-AOR allowlist (gates the
  registered Address-of-Record to defeat registration-hijack).
- v1.12 chunk-7: per-From-domain allowlist (gates the
  From: header domain part).
- v1.17 chunk-2: token-generation cookie (separator 0xFC).

Refusal idiom: SIP/2.0 405 Method Not Allowed with an Allow:
header listing the permitted methods.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would issue
  REGISTER probes against the running endpoint.

## Proxy hooks
Default-build proxy: in-band SIP message decode. OPTIONS,
SUBSCRIBE, NOTIFY (read-class) forward; everything else hits
405.

## Scoring contribution
factors{protocol_risk:70 default → VendorRisk(vendor),
exposure:80, auth_state:60→50 on 401 challenge, capability:
30→60 on SIP reply, impact_class:75 (toll fraud + call
hijack), **cve_exposure:12**, a qualitative baseline with no
specific ids asserted (the earlier list mis-attributed
CVE-2017-3881, a Cisco IOS Smart Install RCE, to SIP; PITF-070)}.

## Sentinel cases
- 200 OK to OPTIONS: SIP confirmed, capability 60.
- 401 challenge: SIP confirmed, capability 60 + auth_state 50
  (407 is not special-cased).
- 405 Method Not Allowed: still SIP confirmed.
- HTTP/1.1 banner: not SIP (vendor=unknown, capability stays
  30).
