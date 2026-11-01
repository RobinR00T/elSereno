# elSereno and MITRE ATT&CK for ICS

elSereno maps each read-only detection to the techniques of **MITRE ATT&CK
for ICS** (matrix version 20) that the observed condition would enable an
adversary to carry out. The mapping lives in `internal/standards`
(`attackics.go`), keyed by protocol, and rides the same pipeline as the
NIST SP 800-82 r4 and ISA/IEC 62443 references: every finding carries them
under `standards` in ndjson, HTML, CEF, syslog, STIX (as
`external_references`) and the Jira/GitHub exporters.

See the full mapping for any protocol with:

```bash
elsereno standards --standard attack-ics
```

## What the mapping is, and is not

ATT&CK for ICS describes adversary **behaviour**, not a device flaw.
elSereno never claims a technique was executed; it names the techniques a
reachable, unauthenticated or writeable surface would let an adversary use.
A reachable TriStation controller, for example, is mapped to Program
Download (T0843) and Change Operating Mode (T0858) because those are the
techniques the protocol exposes, not because a download was seen.

The mapping is elSereno's reading of the matrix. MITRE has not reviewed it.

## Technique hygiene (PITF-104)

ATT&CK for ICS revokes and deprecates technique IDs between versions, and a
stale ID silently points an operator at the wrong behaviour. Against matrix
v20, elSereno uses only current IDs and avoids the ones below, which were
**revoked** (folded into Enterprise ATT&CK) or **deprecated**:

| ID | Status in v20 | Use instead |
|---|---|---|
| T0812 Default Credentials | revoked | T0859 Valid Accounts |
| T0855 Unauthorized Command Message | revoked | T0855 behaviour is covered by T0831 Manipulation of Control |
| T0856 Spoof Reporting Message | revoked | the Enterprise technique it was folded into |
| T0891 Hardcoded Credentials | revoked | T0859 Valid Accounts |
| T0807 Command-Line Interface | deprecated | the Enterprise equivalent |

Each ID elSereno emits was checked against the live technique page; the
lesson of PITF-070 (invented CVE IDs) applies to technique IDs too.

## Techniques elSereno maps today

| Surface | Techniques (v20) |
|---|---|
| Any reachable OT protocol with no authentication | T0886 Remote Services |
| TriStation (`tristation`) | T0888 Remote System Information Discovery, T0843 Program Download, T0858 Change Operating Mode |
| PROFINET-CM (`profinet-cm`) | T0888 Remote System Information Discovery, T0886 Remote Services |
| IT-management service on an OT segment (`it-management`) | T0886 Remote Services, T0859 Valid Accounts |
| Credential reuse accepted (`creds-check reuse`, offensive) | T0859 Valid Accounts |

The `it-management` key is not a protocol plugin: it is the exposure
category (`plaintext-check --list-ports`) for a remote-administration,
database or directory service found where only OT should be.
