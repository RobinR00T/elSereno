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
  maps to the standard. Traceability now reaches all four consumption
  surfaces: ndjson (SIEM), HTML report (reader), GitHub, and Jira.

## Source

NIST SP 800-82r4 ipd (Initial Public Draft), September 2026,
`https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r4.ipd.pdf`.
Quotations are from Appendix C.2.2. This is a draft; re-check the table
numbering and wording against the final publication.
