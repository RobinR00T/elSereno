---
phase: v1.20
status: implemented
last-updated: 2026-04-28
token-budget: 1000
protocol-name: finsudp
default-port: 9600/udp
---

# Omron FINS UDP

## TL;DR
ElSereno's `finsudp` plugin sends a single CONTROLLER DATA READ
datagram (MRC=0x05, SRC=0x01, area=0x00) on UDP/9600 and folds the
parsed 20-byte ASCII Model field into the finding hash. v1.20
chunk 1 ships read-only fingerprint; memory-area writes / RUN-STOP
deferred to a later cycle.

## Spec references
- OMRON CPU Manual W421 (FINS Commands Reference) — canonical.
- ICS-CERT advisories on OMRON CJ/CS lacking authentication.

## Wire format (summary)
13-byte request, ~74-byte response. Frame layout in
`internal/protocols/finsudp/wire/wire.go`:
```
ICF RSV GCT DNA DA1 DA2 SNA SA1 SA2 SID MRC SRC area
0x80 0x00 0x02 0x00 0x00 0x00 0x00 0x01 0x00 SID 0x05 0x01 0x00
```
Response: same header with ICF=0xC0, end code at [12:14], then
20-byte Model + 20-byte InternalCode + optional 20-byte
SystemVersion.

## Fingerprint strategy
One-shot probe. The Model string ("CJ2M-CPU33", "NJ501-1500", etc.)
is the canonical signal — captured into the finding hash so dedup is
per-controller-model. Sentinel-error classification surfaces in the
note: short frame, SID echo mismatch, end-code refusal, wrong
MRC/SRC, or generic non-FINS noise.

## Read operations (default build)
- `probe`: builds a fresh non-zero SID per call (`crypto/rand`),
  dials UDP, sends BuildControllerDataRead, parses with
  ParseControllerDataRead.

## Write / dial operations (offensive build tag)
Deferred. FINS write services include: memory-area write
(MRC=0x01 SRC=0x02), forced-set / forced-set-cancel (0x22..0x24),
bit-set/reset, mode transitions RUN/STOP/RESET (MRC=0x04), program
file transfer (MRC=0x22). Each needs per-area-code + per-mode
allowlist gating analogous to Modbus per-FC and BACnet per-svc.

## REPL commands (planned)
- See the generic REPL framework. Expose ControllerData fields
  (Model, InternalCode, SystemVersion) read-only.

## Proxy hooks
Fail-closed: TCP proxy framework cannot legitimately relay UDP
FINS frames. `ProxyHandler.Handle()` returns immediately with an
error citing the missing UDP relay. A dedicated UDP relay arrives
with a future offensive write plugin (analogous to BACnet's pattern).

## Scoring contribution
factors{protocol_risk:80, exposure:80, auth_state:95, capability:30
(75 on FINS reply), impact_class:75, cve_exposure:0}. impact_class
75 reflects factory-floor PLC blast radius (RUN/STOP, force-set
output bit, program rewrite). auth_state 95 because FINS has no
native authentication — every Internet-exposed CPU on 9600 is a
potential write target if an offensive plugin lands.

## Sentinel errors (wire package)
- ErrShortFrame: < 14-byte response.
- ErrNotResponse: ICF lacks the response bit (0x40), or wrong
  MRC/SRC.
- ErrServiceMismatch: SID echo doesn't match the request.
- ErrEndCodeNonZero: controller refused (end code [12:14] != 0).

These surface to the operator-facing note via `classifyParseError`
(plugin layer).
