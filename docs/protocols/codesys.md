# CoDeSys V3 (TCP 1217)

CoDeSys V3 (formerly 3S-Smart Software Solutions, now CoDeSys
GmbH) is the runtime layer that ships with most modern soft-PLC
vendors: Wago PFC200, Beckhoff (alt-runtime), Eaton, Bosch
Rexroth, ABB AC500, Hilscher netX, Schneider M251/M258/M262,
Festo CMMP/CMMS, plus dozens of smaller automation-component
vendors. The CoDeSys Gateway-Server binds TCP/1217 by default;
some installations also expose 11740 (newer) or 1200 (V2 legacy).

## Probe

- Send the 4-byte BlockDriver magic hello: `0xCD 0xCD 0xCD 0xCD`.
- Classify the response by either:
  - **BlockDriver magic echo** — the server's first 4 bytes
    match the magic, indicating a real CoDeSys V3
    handshake, OR
  - **Banner substring match** — the response contains one of
    the canonical CoDeSys banner strings:
    `CoDeSys`, `CODESYS`, `3S-Smart`, `3S-CoDeSys`,
    `CmpHostname`, `CmpAppBP`, `CmpRuntime`. Some gateways
    prefix a plain-text greeting before the binary handshake.

## Wire layout (BlockDriver)

```
Offset  Field      Size  Description
0..3    Magic      4     0xCD 0xCD 0xCD 0xCD
4..7    Length     4     LE: payload length (excludes header)
8..11   Header     4     LE: protocol header (varies by version)
12..15  Checksum   4     LE: header / payload checksum
16+     Payload    …     APDU (Layer-3 / Layer-4 / Layer-7)
```

The full CoDeSys V3 service-request layer is out of scope for
this fingerprint — we treat all bytes after the 4-byte magic
as opaque. Future offensive plugins would decode the layered
"Layer-3 / Layer-4 / Layer-7" APDU stack to drive specific
service requests.

## Proxy policy (default build)

Fail-closed. CoDeSys V3 is a proprietary tag-length-value
protocol whose deeper layers (Layer-3 / Layer-4 / Layer-7) are
not implemented. The default-build proxy refuses sessions
immediately rather than relay bytes that may or may not be
valid CoDeSys frames — defence-in-depth fail-closed pattern.

## Writes (`-tags offensive`)

Deferred. CoDeSys V3 supports:
- `Cmp`-prefixed service requests (CmpAppBP write app, CmpFile
  write filesystem, CmpUserMgr add user) — full RCE on the PLC
  runtime.
- Plain-text password authentication on un-hardened gateways
  (ICSA-12-242-01); newer versions support OAuth-style auth
  but many deployments don't enforce.
- Project download / upload with optional encryption.

A future offensive plugin would gate per-(Cmp service, target
component) and emit `audit-chain` events per service request.
Triple-confirm + audit-chain emission per ADR-009.

## Scope

- Soft-PLC runtimes across European + global automation
  vendors (Wago, Beckhoff, Eaton, Schneider M251/M258/M262,
  Bosch Rexroth, ABB AC500, Hilscher netX, Festo CMMP/CMMS).
- Some HMI gateways (CoDeSys Visualization Web Server) bridge
  CoDeSys to HTTP/8080.
- Impact: a writeable CoDeSys endpoint can replace the running
  application (CmpAppBP write), add operating-system users
  (CmpUserMgr), or stop the runtime entirely. Affects every
  ICSA advisory on the CoDeSys family.

## Public references

- ICS-CERT advisories ICSA-12-242-01, ICSA-19-080-01,
  ICSA-21-014-04 — multiple CVEs on authentication bypass +
  remote code execution paths.
- nmap NSE script `codesys-info` (community).
- Open-source clients: libcodesys-py, codesys-rs.
- 3S CoDeSys Online Help — protocol reference (registration
  required).
