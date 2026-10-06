---
phase: vNext
status: implemented
last-updated: 2026-10-04
token-budget: 700
protocol-name: melsoft
default-port: 5007/tcp
---

# MELSOFT (GX Works engineering protocol, TCP/5007)

## TL;DR
ElSereno's `melsoft` plugin sends the fixed 41-byte MELSOFT
get-CPU-info request (first byte 0x57) on TCP/5007 and classifies
the reply by its 0xD7 response marker, folding the 16-byte ASCII
CPU model name (offset 41) into the finding hash. Read-only,
fail-closed proxy. Distinct from `slmp` (MC 3E, 0x50/0xD0).

## Why both melsoft and slmp on 5007 (evidence level)
PRIMARY (verified 7-10-2026): on a QnUCPU built-in Ethernet port,
TCP/5007 is the system-reserved "MELSOFT communication port (TCP/IP)"
(SH(NA)-080811ENG, Appendix 2; 5006 = MELSOFT UDP, 5008 = "MELSOFT
direct connection port"). iQ-R lists the same (secondary: pymelsec
README table). E71 modules: TCP/5002 MELSOFT, UDP/5000 auto-open MC
(LJ71E71 manual, Appendix 2, primary). NOT verified: whether the
MELSOFT port also answers an MC 3E frame (the manual reserves it for
MELSOFT, but the pymelsec MC client defaults to 5007). Hence both
plugins on 5007.

## Spec references
- plcscan/DigitalBond melsecq-discover.nse (getcpuinfopack + 0xd7
  response + CPU model at 1-based offset 42).
- Real capture: hi-KK/ICS-Protocol-identify "Mitsubishi Q系列PLC
  CPU型号识别.pcapng" (TCP/5007, Q03UDECPU).
- Mitsubishi SH(NA)-080811ENG (QnUCPU built-in Ethernet), Appendix 2:
  5007 = "MELSOFT communication port (TCP/IP)", system-reserved.
- Mitsubishi SH(NA)-081105ENG (MELSEC-L E71), Appendix 2: 5002 MELSOFT TCP.
- Mitsubishi MELSEC iQ-R/iQ-F/Q/L CPU Module User's Manual.

## Wire format (summary)
Request: fixed 41-byte getcpuinfopack, byte 0 = 0x57, embeds the
0x0101 read-CPU-model command. Response: byte 0 = 0xD7, byte 1 =
0x00, ASCII CPU model name at offset 41 (16-byte field, read up to
the first NUL like the NSE, space padding trimmed).
Validated byte-for-byte against the real capture (BuildGetCPUInfo
== capture request; ParseCPUInfo extracts "Q03UDECPU").

## Fingerprint strategy
One-shot probe over TCP: send getcpuinfopack, accumulate until a
model is readable or the peer goes quiet, classify by the 0xD7
marker. A valid marker with no room for a model is still a positive
ID (empty model).

## CVE enrichment
Model prefix -> cve.ForSLMP (shared MELSEC-model-to-CVE map):
iQ-F/FX5 -> CVE-2025-7731 + CVE-2024-8403; iQ-R -> CVE-2020-5668;
classic Q/L/legacy FX -> baseline only. Family-level, NVD-verified.

## Read operations (default build)
- `probe`: dials TCP/5007, sends BuildGetCPUInfo (41 bytes), reads
  the reply, classifies via IsResponseFrame + ParseCPUInfo.

## Proxy hooks
Fail-closed: the MELSOFT service layer (program/parameter transfer,
RUN/STOP) is a proprietary TLV stack not modelled here, so the
default-build proxy refuses the session. No offensive write path.

## Scoring contribution
factors{protocol_risk:80, exposure:75, auth_state:95, capability:30
(75 on MELSOFT reply), impact_class:75, cve_exposure:10 baseline
(raised by cve.ForSLMP on an iQ-F/iQ-R model)}. auth_state 95: the
MELSOFT communication port has no native authentication.

## Sentinel errors (wire package)
- ErrShortFrame: response shorter than the 2-byte marker.
- ErrNotResponse: byte 0 is not 0xD7 (not a MELSOFT reply).
