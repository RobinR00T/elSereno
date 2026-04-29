---
phase: v1.22
status: implemented
last-updated: 2026-04-28
token-budget: 800
protocol-name: codesys
default-port: 1217/tcp
---

# CoDeSys V3

## TL;DR
ElSereno's `codesys` plugin sends a 4-byte BlockDriver magic
hello (0xCD 0xCD 0xCD 0xCD) on TCP/1217 and classifies the
response by either:
- BlockDriver magic echo (response prefix matches the magic), or
- Canonical CoDeSys banner substring (CoDeSys / CODESYS /
  3S-Smart / 3S-CoDeSys / CmpHostname / CmpAppBP / CmpRuntime).

v1.22 chunk 2 ships read-only fingerprint with a fail-closed
proxy.

## Spec references
- ICS-CERT ICSA-12-242-01 / 19-080-01 / 21-014-04 — CVE families.
- nmap NSE script `codesys-info` (community).
- Open-source clients: libcodesys-py, codesys-rs.

## Wire format (summary)
4-byte BlockDriver magic `0xCD 0xCD 0xCD 0xCD` opens every
CoDeSys V3 BlockDriver frame. Frame layout in
`internal/protocols/codesys/wire/wire.go`. Deeper Layer-3 /
Layer-4 / Layer-7 APDU stack is out of scope for v1.22 chunk 2.

## Fingerprint strategy
One-shot probe over TCP. Send the 4-byte magic, read up to 1024
bytes. Two positive-ID paths cover both binary-handshake
gateways (magic echo) and gateways that prefix a plain-text
greeting before the binary handshake (banner substring match).

## Read operations (default build)
- `probe`: dials TCP/1217, sends BuildHello (4 bytes), reads up
  to 1024 bytes, classifies via Classify (BlockDriver magic OR
  banner substring).

## Write / dial operations (offensive build tag)
Deferred. CoDeSys V3 supports Cmp* service requests (CmpAppBP
write app, CmpFile write filesystem, CmpUserMgr add user) —
full RCE on the PLC runtime — plus project download/upload with
optional encryption.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would issue
  CmpHostname / CmpInformation read requests to enumerate the
  PLC runtime version + project name.

## Proxy hooks
Fail-closed: the proprietary tag-length-value stack is not
implemented in v1.22 chunk 2; the default-build proxy refuses
sessions immediately rather than relay bytes that may or may not
be valid CoDeSys frames.

## Scoring contribution
factors{protocol_risk:80, exposure:75, auth_state:85, capability:30
(70 on CoDeSys reply), impact_class:75, cve_exposure:10}.
- protocol_risk 80: soft-PLC runtime, kinetic effects.
- auth_state 85: CoDeSys V3 supports password / OAuth but many
  deployments don't enforce.
- impact_class 75: factory-floor PLC blast radius.
- cve_exposure 10: ICSA-12-242-01 / 19-080-01 / 21-014-04 are
  well-known CVEs in the family — first plugin to set
  cve_exposure non-zero by default.

## Sentinel errors (wire package)
- ErrShortFrame: < 4-byte response.
- ErrNotCoDeSys: response neither leads with magic nor carries
  a banner substring.
