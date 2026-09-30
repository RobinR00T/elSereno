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
| `opcua probe-anon` (anonymous session opens on a SecurityMode=None endpoint) | "Authentication ... nonexistent" (Table 16) |
| `opcua probe-write` (address-space tags writeable by the anonymous user) | "Without authentication, there is the potential to replay, modify, or spoof data or devices" (Table 16) |
| Modbus reachability + no native auth (`modbus monitor`, fingerprint) | "Use of unsecure OT protocols"; "OT protocols often have few or no security capabilities" (Table 16) |
| `discover` / `fingerprint` surfacing reachable OT ports across zones | "Poor configurations ... unnecessary ports and protocols open" (Table 13); "Firewalls are nonexistent or improperly configured" (Table 16) |
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

Detections the draft calls for that elSereno could add (tracked in
`TODO-vNext.md`):

- **Plaintext-protocol exposure finding.** Table 16: "Standard,
  well-documented communication protocols are used in plaintext" (telnet,
  FTP, HTTP, NFS). Flag cleartext services on OT hosts explicitly.
- **Default-credential check (opt-in, `offensive` build tag, authorized use
  only).** Table 13: "Vendor default passwords are used ... easy to discover
  within vendor product manuals." Gated behind the same dual-use controls as
  the write-gates.
- **Standards traceability in findings.** Tag each exposure finding with the
  SP 800-82 r4 vulnerability it evidences, so a run is auditable against the
  standard.

## Source

NIST SP 800-82r4 ipd (Initial Public Draft), September 2026,
`https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r4.ipd.pdf`.
Quotations are from Appendix C.2.2. This is a draft; re-check the table
numbering and wording against the final publication.
