# elSereno and Cyber-Informed Engineering (CIE)

**Cyber-Informed Engineering** is the DOE (CESER) and INL approach for
building cybersecurity into an OT system from design through operation,
so the worst consequences are "engineered out" rather than only
monitored. DOE CESER, announcing the SP 800-82 r4 Initial Public Draft on
LinkedIn (6 November 2026), presents CIE as the kind of engineering-based
method the draft encourages; the NIST announcement page itself does not
name CIE. CIE is a set of twelve **principles**, not a control
catalogue. elSereno maps each read-only detection to the principles a
finding is a **network-visible sign were not applied** to that system.
The mapping lives in `internal/standards/cie.go`, keyed by protocol, and
is carried alongside the other references in every output.

See the mapping with:

```bash
elsereno standards --standard cie
```

```bash
elsereno standards --standard cie --protocol tristation
```

```text
tristation
    DOE CIE Principle 1: Consequence-Focused Design
    DOE CIE Principle 2: Engineered Controls
    DOE CIE Principle 3: Secure Information Architecture
    DOE CIE Principle 5: Layered Defenses
```

Principle numbers and names were checked against the CIE Implementation
Guide v1.0 and are pinned by `TestCIEPrinciples`. The mapping is
elSereno's reading, not a DOE or INL assessment.

## The principles elSereno touches

| # | Principle | Evidenced by |
|---|---|---|
| 1 | Consequence-Focused Design | a safety instrumented system (TriStation) reachable from the network: the consequence CIE designs out first |
| 2 | Engineered Controls | protection that should be engineered (key switch, CPU protection level, read-only nodes) but is open over the network: TriStation, `s7-exposure`, `opcua-exposure` |
| 3 | Secure Information Architecture | any unauthenticated OT protocol: a client on the path can read or alter process data; anonymous MQTT |
| 4 | Design Simplification | IT management services (RDP, SMB, MS SQL, ...) on an OT segment: features the critical function does not need |
| 5 | Layered Defenses | any OT protocol or remote link the scanner reached: no layer in between stopped it |
| 7 | Interdependency Evaluation | AT modems, TR-069 (CWMP) and IT services one hop from OT: links that tie the system to outside parties |

## What elSereno does not map

Principles 6 (Active Defense), 8 (Digital Asset Awareness), 9
(Cyber-Secure Supply Chain Controls), 10 (Planned Resilience), 11
(Engineering Information Control) and 12 (Organizational Culture) are
about processes, people and design records a network scan cannot see.
elSereno's discovery output is **input** to Digital Asset Awareness (it
tells you what answers on the wire), but a found device is not evidence
the principle failed unless it is missing from your inventory, which
elSereno does not know. Telephony and X.25 plugins (SIP, IAX2, XOT, PBX
HTTP) carry no CIE mapping.

## Legacy plants

CIE is written for the whole lifecycle, including systems that are
already running and cannot be redesigned. For those, the mapping points
at what can still change without a redesign: close the path (Principle
5), remove services the process does not need (Principle 4), and put the
SIS key switch back in RUN (Principle 2). `elsereno tristation --passive`
reads a capture without touching the controller.

## Source

Idaho National Laboratory, *Cyber-Informed Engineering Implementation
Guide*, INL/RPT-23-74072, Version 1.0, 7 August 2023, OSTI 1995796,
`https://www.osti.gov/biblio/1995796`. DOE CESER CIE programme:
`https://www.energy.gov/ceser/cyber-informed-engineering`.

## Related mappings

[nist-sp800-82r4.md](nist-sp800-82r4.md), [nist-csf-2.0.md](nist-csf-2.0.md),
[mitre-attack-ics.md](mitre-attack-ics.md), [iec62443-3-3.md](iec62443-3-3.md).
