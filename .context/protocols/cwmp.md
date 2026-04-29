---
phase: F4
status: implemented
last-updated: 2026-04-29
token-budget: 800
protocol-name: cwmp
default-port: 7547/tcp
---

# CWMP / TR-069

## TL;DR
ElSereno's `cwmp` plugin probes TCP/7547 with an HTTP HEAD
request and classifies the response as `cwmp-likely` /
`non-cwmp-http` / silent. Vendor detection runs against
`Server:` / `WWW-Authenticate:` realm strings to identify the
ACS (Auto-Configuration Server) family or the underlying CPE
(broadband modem / IP phone / IoT gateway). Offensive write
plugin gates per-(SOAP-RPC, parameter-prefix, firmware-URL)
since v1.12.

## Spec references
- TR-069 Issue 1 Amendment 6 (CWMP — CPE WAN Management
  Protocol).
- TR-098 / TR-181 (Internet Gateway Device data model).
- TR-064 (LAN-side DSL CPE configuration; the
  `NewNTPServer` injection family).

## Wire format
HTTP/1.1 with SOAP/1.1 envelope payloads. The CPE → ACS
direction carries Inform / TransferComplete / Connection
Request notifications; the ACS → CPE direction carries
Set/GetParameterValues / Download / Upload / Reboot / Factory
Reset RPCs.

The fingerprint probe is plain HTTP HEAD / OPTIONS with no
SOAP body — it relies on the `Server:` header + 401 challenge
shape to identify CWMP-bearing endpoints.

## Fingerprint strategy
Two-stage:
1. HTTP HEAD `/` with timeout. Capture status code + Server +
   WWW-Authenticate.
2. Vendor detection against the `Server:` value (RomPager /
   GoAhead / mini_httpd / lighttpd / Cisco IOS / etc.) and any
   401 realm string.

CWMP-likely heuristic: status 401 with "TR069" / "TR-069" /
"CWMP" / "ACS" in the realm OR a Server header from a known
ACS / CPE vendor.

## Read operations (default build)
- `probe`: HEAD `/` against TCP/7547 with vendor classification.

## Write / dial operations (offensive build tag)
v1.11+ landed `offensive/write/cwmp/gatedproxy.go` with full
SOAP-RPC gating:
- per-RPC allowlist (Set/GetParameterValues, Download,
  Reboot, FactoryReset, Upload, etc.).
- per-parameter-prefix allowlist (e.g.,
  `Device.Time.NTPServer1` only — not the whole
  `Device.Time.*` tree).
- per-firmware-URL allowlist for Download RPCs (v1.12-chunk-10
  matches the URL against an exact list AND captures the
  firmware SHA-256 in the audit chain).
- v1.16 chunk-1 closed the TransferComplete observer half:
  parses CPE → ACS TransferComplete envelopes and
  cross-references the Authorisation captured at Download time.
- v1.19 chunk-3 added the async firmware re-fetch (opt-in via
  `--verify-firmware-on-complete --verify-firmware-timeout
  5m`) which streams + hashes the URL post-flash and emits a
  `cwmp_firmware_verify` audit event on hash mismatch (catches
  source-server firmware swaps post-flash).

Refusal idiom: SOAP Fault FaultCode 9001 ("Request denied")
or 9005 ("Invalid parameter name") per TR-069 Annex A.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would issue
  GetParameterValues / GetParameterNames against the CPE's
  data model.

## Proxy hooks
v1.5+ ships the in-band CWMP proxy at port 7547. Default-build
proxy refuses every SOAP RPC with Fault 9001 before forwarding
to upstream — even GetParameterValues is refused (the protocol
is by design write-capable end-to-end and we don't want to
forward read-only frames as cover for write payloads).

Offensive proxy decodes the SOAP envelope, walks the Body
RPC, and gates per the 3 allowlist dimensions described
above.

## Scoring contribution
factors{protocol_risk:30→80 on cwmp-likely, exposure:80,
auth_state:60, capability:30→60 on cwmp-likely, impact_class:
50, **cve_exposure:15** (CVE-2014-9222 Misfortune Cookie /
RomPager + TR-064 NewNTPServer family — broad legacy CPE
exposure on the same port 7547 ACS endpoint)}.

cve_exposure 15 is the highest in the entire codebase
(v1.23 chunk 1) — TR-069 / 7547 carries one of the most
extensively-exploited CVE families in the ICS-adjacent
landscape.

## Sentinel cases
- 401 with TR069 realm: cwmp-likely + auth_state 60.
- 200 with HTTP body containing CWMP headers: cwmp-likely.
- Plain HTTP banner: non-cwmp-http (capability stays 30).
- Silent / RST: no usable reply.
