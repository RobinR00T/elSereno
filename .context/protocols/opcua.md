---
phase: F4
status: implemented
last-updated: 2026-04-29
token-budget: 800
protocol-name: opcua
default-port: 4840/tcp
---

# OPC UA

## TL;DR
ElSereno's `opcua` plugin probes TCP/4840 (the canonical UA-TCP
port) with a HEL (Hello) message and classifies the response as
ACK / ERR / non-UA-TCP. Anonymous HEL is always allowed by the
spec, so the fingerprint is reliable across hardened
deployments. Offensive write plugin gates per-NodeId (numeric +
String/GUID/ByteString) and per-CallMethod since v1.12.

## Spec references
- IEC 62541 / OPC 10000-6 (UA Mappings — UA-TCP framing).
- OPC 10000-3 (Address Space Model).
- OPC 10000-4 (Services — Read / Write / Call / Browse).

## Wire format
UA-TCP message types (4-byte ASCII MessageType + Reserved + 4-
byte LE MessageSize):
- HEL: Hello (client → server, opens transport).
- ACK: Acknowledge (server → client).
- ERR: Error (with statusCode + reason string).
- OPN: OpenSecureChannel (TLS-equivalent at app layer).
- MSG: SecureChannel message (Read/Write/Call/etc.).
- CLO: CloseSecureChannel.

The fingerprint probe sends a minimal HEL with proto version 0,
1MB receive buffer, 1MB send buffer, max-message 16MB,
max-chunks 5000. The server responds with ACK (positive ID) or
ERR with a UA-status code (still a positive ID — the server
spoke UA-TCP).

## Fingerprint strategy
One-shot HEL → ACK/ERR. The endpoint URL in the HEL is
`opc.tcp://<target>:4840` (canonical anonymous endpoint).

## Read operations (default build)
- `probe`: HEL → 4840, classify ACK / ERR / non-UA-TCP.

## Write / dial operations (offensive build tag)
v1.6+ landed full `offensive/write/opcua/gatedproxy.go`:
- per-NodeId allowlist for WriteRequest (numeric NodeIds since
  v1.6, String/GUID/ByteString since v1.12).
- per-CallMethod allowlist for CallRequest (gates the
  `(ObjectId, MethodId)` tuple — methods can have arbitrary
  side effects, much higher blast radius than attribute
  writes).
- v1.17 chunk-3 added token-generation cookie folding into the
  hash for SIGUSR1 reload support (separator 0xFB).

Refusal idiom: UA ServiceFault with `BadUserAccessDenied`
(0x80300000) plus a custom diagnostic info reason.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would issue
  GetEndpoints / Browse / Read against the running session.

## Proxy hooks
Default-build proxy: full UA-TCP message-by-message decode.
Read-class messages (Read, Browse, GetEndpoints, HistoryRead)
forward; write-class (Write, Call, HistoryUpdate) hit
ServiceFault BadUserAccessDenied before reaching upstream.

## Scoring contribution
factors{protocol_risk:85, exposure:75, auth_state:60 (anon HEL
always allowed), capability:30→60 on UA-TCP reply,
impact_class:85 (PLC control plane), **cve_exposure:8**
(CVE-2017-12069 Siemens OPC UA stack auth bypass +
CVE-2019-10936 open62541 cert validation + CVE-2022-29862
Unified Automation OPC UA C++ DoS)}.

## Sentinel cases
- ACK message: UA-TCP confirmed, capability lifts to 60.
- ERR message with UA status code: UA-TCP confirmed (server
  spoke the protocol but rejected our HEL — usually due to
  endpoint-URL mismatch or buffer-size negotiation).
- Non-UA-TCP response: capability stays 30.
- Silent: no usable reply.

## Forward work
- OPC UA over HTTPS (port 443 with `opc.https://` scheme) —
  requires a TLS handshake first then UA-TCP framing on top.
  Deferred to v1.24+ (no test vectors yet).
