---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 600
---

# Glossary

- **AUP** — Acceptable Use Policy. See `LEGAL.md` and `internal/scope/`.
- **BACnet** — Building Automation and Control networks; UDP/47808.
- **CAP_NET_RAW** — Linux capability required for raw sockets (e.g. nmap `-sS`).
- **CEF** — Common Event Format (ArcSight).
- **CHECK** — SQL column-level constraint used for enum-like enforcement.
- **CSP** — Content Security Policy (HTTP header).
- **CSRF** — Cross-site request forgery; protection via `gorilla/csrf`.
- **DCO** — Developer Certificate of Origin (Signed-off-by commit trailer).
- **DDoS** — Denial of service (mass).
- **EN 81-28** — European lift (elevator) alarm/interphone standard.
- **Evidence** — Raw bytes captured for a finding; truncated at
  `evidence.max_payload_bytes` with SHA-256 of the full body kept.
- **Finding** — A scored observation about a target produced by a protocol
  plugin.
- **Fingerprint** — Active or passive identification of protocol/vendor.
- **HART-IP** — Highway Addressable Remote Transducer over IP.
- **HKDF** — HMAC-based Key Derivation Function (RFC 5869).
- **ICS/OT** — Industrial Control Systems / Operational Technology.
- **JCS** — JSON Canonicalisation Scheme (RFC 8785).
- **Modbus** — ICS protocol; TCP/502.
- **NDJSON** — Newline-delimited JSON.
- **NSE** — Nmap Scripting Engine.
- **PLC** — Programmable Logic Controller.
- **Probe** — Protocol plugin entry-point that fingerprints a target.
- **REPL** — Read-eval-print loop (interactive shell over a protocol).
- **Run** — A single execution with a scope and input set.
- **S7comm** — Siemens S7 communications; TCP/102.
- **SBOM** — Software Bill of Materials (CycloneDX).
- **Scope** — Authorised target range; lives in `scope.yaml`.
- **Session** — A stateful interaction (REPL, proxy) with a target.
- **SLSA** — Supply-chain Levels for Software Artifacts (SLSA L3 provenance).
- **Target** — `(address, port)` tuple.
- **Triage** — Grouping of findings into quick-wins and strategic sets.
- **Vault** — Encrypted credential store (AES-GCM + Argon2id).
- **XOT** — X.25 over TCP (RFC 1613).
