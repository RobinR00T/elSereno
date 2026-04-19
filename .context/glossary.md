---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 800
---

# Glossary

## General
- **AUP** — Acceptable Use Policy. See `LEGAL.md` and `internal/scope/`.
- **CAP_NET_RAW** — Linux capability required for raw sockets (e.g. nmap `-sS`).
- **CEF** — Common Event Format (ArcSight).
- **CHECK** — SQL column-level constraint used for enum-like enforcement.
- **CSP** — Content Security Policy (HTTP header).
- **CSRF** — Cross-site request forgery; protection via `gorilla/csrf`.
- **DCO** — Developer Certificate of Origin (Signed-off-by commit trailer).
- **DDoS** — Denial of service (mass).
- **Evidence** — Raw bytes captured for a finding; truncated at
  `evidence.max_payload_bytes` with SHA-256 of the full body kept.
- **Finding** — A scored observation about a target produced by a protocol
  plugin.
- **Fingerprint** — Active or passive identification of protocol/vendor.
- **HKDF** — HMAC-based Key Derivation Function (RFC 5869).
- **ICS/OT** — Industrial Control Systems / Operational Technology.
- **JCS** — JSON Canonicalisation Scheme (RFC 8785).
- **NDJSON** — Newline-delimited JSON.
- **NSE** — Nmap Scripting Engine.
- **PLC** — Programmable Logic Controller.
- **Probe** — Protocol plugin entry-point that fingerprints a target.
- **REPL** — Read-eval-print loop (interactive shell over a protocol).
- **Run** — A single execution with a scope and input set.
- **SBOM** — Software Bill of Materials (CycloneDX).
- **Scope** — Authorised target range; lives in `scope.yaml`.
- **Session** — A stateful interaction (REPL, proxy) with a target.
- **SLSA** — Supply-chain Levels for Software Artifacts (SLSA L3 provenance).
- **Target** — `(address, port)` tuple.
- **Triage** — Grouping of findings into quick-wins and strategic sets.
- **Vault** — Encrypted credential store (AES-GCM + Argon2id).

## Protocol terms

### Modbus/TCP (port 502)
- **MBAP** — Modbus Application Protocol header: TxID / ProtocolID (always
  0x0000) / Length / Unit (7 bytes).
- **PDU** — Protocol Data Unit: `[FC][data…]` up to 253 bytes.
- **FC** — Function Code. FC | 0x80 in a response signals an exception.
- **MEI** — Modbus Encapsulated Interface (FC 43). Sub-code 0x0E is
  Read Device Identification (the only MEI sub-code the proxy forwards).

### S7comm (Siemens, port 102)
- **TPKT** — RFC 1006 4-byte envelope: Version=0x03 / Reserved / Length.
- **COTP** — ISO 8073 connection-oriented transport. CR=0x0E, CC=0x0D,
  DR=0x08, DT=0x0F PDU types.

### EtherNet/IP CIP (port 44818)
- **CIP** — Common Industrial Protocol (ODVA).
- **Encapsulation** — The 24-byte TCP header wrapping a CIP service.
- **ListIdentity** — Command 0x0063. Returns an Identity object (VendorID,
  DeviceType, ProductCode, Revision, SerialNumber, ProductName).

### BACnet (ASHRAE 135, UDP 47808)
- **BVLC** — BACnet Virtual Link Control (4-byte outermost header).
- **NPDU / APDU** — Network / Application PDUs inside BVLC.
- **Who-Is / I-Am** — Broadcast discovery + unicast reply pair.

### DNP3 (IEEE 1815, port 20000)
- **Start bytes** — 0x05 0x64, the data-link frame magic.
- **Class 0** — All static data; Read Class 0 is the most minimal probe.

### IEC 60870-5-104 (power SCADA, port 2404)
- **APCI** — Application Protocol Control Information (6-byte APDU header).
- **TESTFR** — "Test Frame" keepalive. U-format frames in general test
  whether the peer speaks IEC-104.

### HART-IP (process instrumentation, port 5094)
- **HART** — Highway Addressable Remote Transducer.
- **Session initiate** — Message-ID 0x00, the first request a client sends.

### Niagara Fox (Tridium, ports 1911/4911)
- Banner-based. Line 1 starts "fox a 0 -1 fox hello\n"; `fox.version=…`
  follows in the body.

### ATG Veeder-Root (fuel tank, port 10001)
- **TLS-350/4** — The Veeder-Root tank-gauge product family.
- **I20100** — "System status" command; the classic fingerprint probe.

### XOT (RFC 1613, port 1998)
- Classic X.25 over TCP. 4-byte XOT envelope + X.25 packet.

### AT modem (Hayes / GSM / EN 81-28)
- **EN 81-28** — European standard for lift alarm / interphone systems.
- **+CME / +CMS ERROR** — GSM-extended error codes (Equipment / SMS).

## External tooling
- **Conpot** — Low-interaction ICS honeypot (Modbus / S7 / ENIP / BACnet /
  HART-IP / IEC-104 / Fox / ATG emulation). Pulled into
  `simulators/docker-compose.test.yml` for broad integration coverage.
- **pymodbus** — Python Modbus library with `pymodbus.simulator`; an
  alternative to our Go `modbus-sim` when operators want a richer PLC.
- **nmap** — External CLI ElSereno does not drive directly but whose
  XML output we parse via `internal/inputs/nmapxml`.
