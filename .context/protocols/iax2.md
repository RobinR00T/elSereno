---
phase: F3
status: implemented
last-updated: 2026-04-29
token-budget: 700
protocol-name: iax2
default-port: 4569/udp
---

# IAX2

## TL;DR
ElSereno's `iax2` plugin sends an IAX2 NEW frame on UDP/4569
and classifies the response by frame subclass (ACCEPT /
AUTHREQ / REJECT / HANGUP). IAX2 is Asterisk-specific
(Inter-Asterisk Exchange v2) so a positive ID is high-signal
for "Asterisk PBX listening". Offensive write plugin gates
per-IAX2-subclass since v1.4.

## Spec references
- IETF draft-guy-iax-04 (informational; IAX2 is Asterisk-
  specific, never IETF-standardised).
- Asterisk source `main/iax2.c` for canonical frame layouts.

## Wire format
Length-prefixed binary frames over UDP/4569. Two frame
classes:
- Full frames: contain a Class + Subclass + DCallNo + SCallNo
  + Timestamp + ISeqNo + OSeqNo (12-byte header + IEs).
- Mini frames: 4-byte header (just SCallNo + Timestamp) for
  voice payloads.

The probe builds a Full Frame with class=IAX (6) and
subclass=NEW (1), with IEs for `username` + `password` (empty
strings to elicit AUTHREQ if creds are required).

## Fingerprint strategy
Send NEW frame, read response:
- ACCEPT (subclass 7): IAX2 confirmed, server allowed
  unauth registration → high capability.
- AUTHREQ (subclass 6): IAX2 confirmed, server requires
  creds → still positive ID, slightly lower capability
  (harder to exploit as toll-fraud).
- REJECT (subclass 9): IAX2 confirmed, server explicitly
  refused → still positive ID.
- HANGUP (subclass 5): IAX2 confirmed, server ended early.
- UDP closed / silent: no usable reply.

## Read operations (default build)
- `probe`: NEW frame to UDP/4569.

## Write / dial operations (offensive build tag)
v1.4+ landed `offensive/write/iax2/gatedproxy.go`:
- per-subclass allowlist (NEW, AUTHREQ, AUTHREP, ACCEPT,
  HANGUP, REJECT, ACK, INVAL, LAGRQ, LAGRP, REGREQ, REGAUTH,
  REGACK, REGREL, REGREJ, VNAK, DPREQ, DPREP, DIAL, TXREQ,
  TXCNT, TXACC, TXREADY, TXREL, TXREJ, INQUIRY, INQUIRYACC,
  INQUIRYREJ, MWI, UNSUPPORT, TRANSFER, PROVISION, FWDOWNL,
  FWDATA, TXMEDIA, RTKEY, CALLTOKEN). REGREQ + DIAL are
  the kinetic-toll-fraud surfaces.
- v1.17 chunk-3: token-generation cookie (separator 0xFC).

Refusal idiom: IAX2 HANGUP frame with a custom CAUSE IE.

## REPL commands (planned)
- See the generic REPL framework.

## Proxy hooks
Default-build proxy is wire-layer write-ban: every frame is
refused with HANGUP before reaching upstream.

## Scoring contribution
factors{protocol_risk:70→90 on IAX2 confirmed, exposure:80,
auth_state:60, capability:30→60 on IAX2 reply, impact_class:
75, **cve_exposure:9** (Asterisk IAX2 family CVE-2007-3764 +
CVE-2008-3263 + CVE-2009-3727 + CVE-2014-9374 — narrower
than SIP's CVE-2009-1207 family but with high toll-fraud
value)}.

## Sentinel cases
- ACCEPT: server allowed unauth NEW, full open.
- AUTHREQ: creds required, still positive ID.
- HANGUP: refused but confirmed.
- Silent: no usable reply.
