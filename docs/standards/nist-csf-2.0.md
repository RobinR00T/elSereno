# elSereno and the NIST Cybersecurity Framework 2.0

NIST SP 800-82 Rev. 4 (Initial Public Draft, 21 September 2026) is
restructured around the **NIST Cybersecurity Framework (CSF) 2.0** (NIST
CSWP 29, February 2024): its OT countermeasures are filed under CSF
Functions, Categories and Subcategories. elSereno maps each read-only
detection to the CSF 2.0 **subcategories** a finding is evidence are not
achieved on that segment, so a run can be read in the same structure as
the draft. The mapping lives in `internal/standards/csf2.go`, keyed by
protocol, and is carried alongside the other references in every output.

See the mapping with:

```bash
elsereno standards --standard csf2
```

```bash
elsereno standards --standard csf2 --protocol modbus
```

```text
modbus
    NIST CSF 2.0 PR.AA-03: Users, services, and hardware are authenticated
    NIST CSF 2.0 PR.IR-01: Networks and environments are protected from unauthorized logical access and usage
```

The subcategory IDs and text were checked against the CSWP 29 PDF and are
pinned by `TestCSF2Subcategories`. The mapping is elSereno's reading, not
a NIST assessment.

## The subcategories elSereno touches

| Subcategory | Outcome | Evidenced by |
|---|---|---|
| PR.AA-03 | Users, services, and hardware are authenticated | any unauthenticated OT protocol (Modbus, S7, DNP3, ...), anonymous OPC UA, anonymous MQTT |
| PR.AA-05 | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed | S7 protection level off (`s7-exposure`), writeable OPC UA nodes (`opcua-exposure`), MQTT with no ACL |
| PR.DS-02 | The confidentiality, integrity, and availability of data-in-transit are protected | plaintext management and telephony protocols (AT modem, CWMP, SIP, IAX2, XOT, PBX HTTP) |
| PR.PS-01 | Configuration management practices are established and applied | security left off by default (`s7-exposure`), unneeded IT management services on an OT segment |
| PR.IR-01 | Networks and environments are protected from unauthorized logical access and usage | any OT protocol or IT management service the scanner reached: the path was open |

## Zero trust

The draft also applies zero trust principles to OT. elSereno does not
carry a separate zero trust catalogue: the network-observable side of
zero trust (every device and service authenticates, no implicit trust
from network location) is what PR.AA-03 and PR.IR-01 already record.

## What elSereno does not map

Govern (GV), Detect (DE), Respond (RS) and Recover (RC) outcomes, and the
asset-inventory outcomes of Identify (ID.AM), are about the organisation's
processes. A network scan is input to them (its findings feed an inventory
and a vulnerability record, ID.RA-01) but it is not evidence that they
fail, so elSereno claims no mapping there.

## Source

NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29, February 2024,
`https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf`.
SP 800-82 r4 IPD announcement: `https://csrc.nist.gov/pubs/sp/800/82/r4/ipd`.

## Related mappings

[nist-sp800-82r4.md](nist-sp800-82r4.md), [mitre-attack-ics.md](mitre-attack-ics.md),
[iec62443-3-3.md](iec62443-3-3.md), [doe-cie.md](doe-cie.md).
