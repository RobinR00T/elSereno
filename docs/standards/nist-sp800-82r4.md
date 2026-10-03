# elSereno and NIST SP 800-82 Rev. 4

This maps elSereno's read-only network detections to the OT vulnerabilities
in **NIST SP 800-82 Rev. 4, *Guide to Operational Technology (OT)
Security*** (Initial Public Draft, September 2026; public comment period
open through 30 November 2026).

elSereno is a network-side, read-only exposure auditor. It cannot observe
physical, policy, or host-internal conditions, so it maps only onto the
**network- and configuration-observable** vulnerabilities of the draft:
Appendix C.2.2, Tables 13 (Configuration and maintenance), 15 (Software
development), and 16 (Communication and network configuration).

## What elSereno detects, and the vulnerability it evidences

| elSereno detection | SP 800-82 r4 vulnerability (table) |
|---|---|
| `s7 probe-protection` / `s7 probe` / `s7-exposure` plugin (effective protection level 0/1 = writable/controllable without a password) | "Authentication of users, data, or devices is substandard or nonexistent"; "Use of unsecure OT protocols" (Table 16) |
| S7 protection level left unset by default | "Installed security capabilities are not enabled by default" (Table 15) |
| `opcua probe-anon` / `opcua-exposure` plugin (anonymous session opens on a SecurityMode=None endpoint) | "Authentication ... nonexistent" (Table 16) |
| `opcua probe-write` / `opcua-exposure` plugin (address-space tags writeable by the anonymous user) | "Without authentication, there is the potential to replay, modify, or spoof data or devices" (Table 16) |
| Modbus reachability + no native auth (`modbus monitor`, fingerprint) | "Use of unsecure OT protocols"; "OT protocols often have few or no security capabilities" (Table 16) |
| `discover` / `fingerprint` surfacing reachable OT ports across zones | "Poor configurations ... unnecessary ports and protocols open" (Table 13); "Firewalls are nonexistent or improperly configured" (Table 16) |
| `plaintext-check` (service reachable but does not negotiate TLS) | "Standard, well-documented communication protocols are used in plaintext" (Table 16) |
| `plaintext-check` TLS posture (service negotiates TLS but still accepts deprecated TLS 1.0 / 1.1, or presents an expired certificate) | "Authentication of users, data, or devices is substandard or nonexistent"; substandard encryption (Table 16) |
| `creds-check http` (published default credentials accepted; offensive build, authorized use only) | "Vendor default passwords are used ... easy to discover within vendor product manuals" (Table 13) |
| `s7 probe-identity`, ENIP ListIdentity, Modbus device identification (exact model + firmware) | "Hardware, firmware, and software that are not under asset/configuration management"; the patch-window vulnerabilities (Table 13) |

The draft names, as its first communication-and-network vulnerability, that
"Many OT protocols have no authentication at any level." elSereno's exposure
probes are precisely the network detection for that condition: they do not
assert the vulnerability from a banner, they confirm it on the wire
(protection level read, anonymous session opened, writeable tag found), each
validated byte for byte against a real capture where one exists.

## Deliberately out of scope for a network probe

These SP 800-82 r4 vulnerabilities are real but not network-observable from a
read-only probe, so elSereno does not claim them: physical access (Table 17),
policy and procedure gaps (Table 11), patch-management status and backup
practice (Table 13, host-internal), and malware-protection state (Table 13).
An operator pairs elSereno's network evidence with host and process
inventory to cover them.

## Roadmap from the draft

Done:

- **Plaintext-protocol exposure check** (`plaintext-check`, 30-9). Table 16.
- **Default-credential check** (`creds-check http`, `offensive` build,
  authorized use only, 30-9). Table 13.
- **Weak-TLS posture in `plaintext-check`** (3-10). When a service does
  negotiate TLS, the check confirms whether it still accepts the
  deprecated TLS 1.0 / 1.1 versions (each with a version-pinned handshake,
  since a modern negotiated version does not imply an obsolete one is
  refused) and whether its leaf certificate has expired, reported as
  `weak_tls` / `deprecated_tls` / `cert_expired`. Read-only, at most three
  short handshakes. Table 16. `internal/exposure/cleartext.go`.
- **Standards traceability in findings** (1-10). Each finding in the ndjson
  output carries a `standards` array with the SP 800-82 r4 vulnerabilities it
  evidences, derived from its protocol; `elsereno standards` prints the full
  protocol-to-vulnerability catalog. The mapping lives in
  `internal/standards/sp80082r4.go`.
- **Standards traceability in the HTML report** (1-10). Each per-protocol
  section of the HTML report shows, inline, the SP 800-82 r4 vulnerabilities
  that protocol's findings evidence, so a human reader (not just a machine
  parsing ndjson) sees the mapping in the report an operator hands to a
  client. Same source of truth (`internal/standards`); a protocol with no
  mapping shows no block.
- **Standards traceability in remediation tickets** (1-10). The GitHub
  Issues and Jira sinks cite the SP 800-82 r4 vulnerabilities in the issue
  body / ADF description and add a filterable `standard/nist-sp800-82r4`
  (GitHub) / `standard:nist-sp800-82r4` (Jira) label, so the remediation
  owner sees the clause the finding evidences and can list every issue that
  maps to the standard.
- **Standards traceability in CEF / syslog** (2-10). The CEF writer carries
  the vulnerabilities in the `cs3` custom string (`cs3Label=standard`); the
  RFC 5424 syslog writer carries them in a `standard` structured-data param.
  Both are the formats an OT SOC's SIEM (ArcSight, QRadar) ingests, so a
  correlation or compliance rule can key on the clause. The flat-string
  join lives in `standards.Summarise`.
- **Standards traceability in STIX / webhook** (2-10). The STIX 2.1 bundle
  cites the vulnerabilities in the observed-data SDO's native
  `external_references` (`source_name` + `description`); the generic webhook
  envelope carries them in a `standards` array, mirroring ndjson. With this,
  every output surface carries the traceability **except CSV**, which is left
  out on purpose: its `csv:v1` header is a stable contract and adding a
  column would break it (it would need a `csv:v2`). The traceability reaches
  ndjson, the HTML report, GitHub, Jira, CEF, syslog, STIX, and webhook,
  plus the `standards` catalog.

## Source

NIST SP 800-82r4 ipd (Initial Public Draft), September 2026,
`https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r4.ipd.pdf`.
Quotations are from Appendix C.2.2. This is a draft; re-check the table
numbering and wording against the final publication.
