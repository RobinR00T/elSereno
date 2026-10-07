# MELSOFT (port 5007)

MELSOFT is the Mitsubishi Electric engineering protocol that GX
Works2 / GX Works3 (and the MELSOFT transparent gateway) speak to a
MELSEC CPU over Ethernet. It is **distinct from SLMP** (MC 3E): MELSOFT
frames carry a 0x57 (request) / 0xD7 (response) marker, where SLMP uses
a 0x50/0xD0 subheader. ElSereno ships both: `melsoft` for MELSOFT and
`slmp` for an MC-3E-configured endpoint.

**Ports, with their evidence level.** On a QnUCPU built-in Ethernet
port, TCP/5007 is the system's "MELSOFT communication port (TCP/IP)":
Mitsubishi's *QnUCPU User's Manual (Communication via Built-in Ethernet
Port)*, SH(NA)-080811ENG, Appendix 2 ("Port Numbers Used by Built-in
Ethernet Port QCPU"), which reserves 5006 (MELSOFT UDP), 5007 (MELSOFT
TCP) and 5008 (the "MELSOFT direct connection port") for the system.
iQ-R lists the same numbers (secondary source: the table in the pymelsec
README). The real Q03UDECPU capture answered on 5007. Mitsubishi E71
Ethernet modules use TCP/5002 for MELSOFT instead (LJ71E71 manual,
Appendix 2: 5000 UDP auto-open, 5001 MELSOFT UDP, 5002 MELSOFT TCP);
probe them with `--target host:5002`.

## Probe

- Send the fixed 41-byte MELSOFT "get CPU info" request (first byte
  0x57; it embeds the 0x0101 read-CPU-model command).
- A real MELSEC CPU replies with a frame that starts `D7 00`.
- The ASCII CPU model name at offset 41 (up to 16 bytes, read up to the
  first NUL like the reference NSE, padding trimmed: "Q03UDECPU",
  "R04ENCPU", "FX5U-32MT/ES", ...) is folded into the finding hash so
  dedup is per-controller-model. A valid 0xD7 frame too short to carry a
  model is still a positive MELSOFT identification (empty model).

The probe is side-effect-free: get-CPU-info returns the CPU's
self-description and touches no memory devices, latches, or program
memory.

## Wire layout

```
Request (41 bytes, fixed):
  Offset  Field            Value
  0       Request marker   0x57
  1       (reserved)       0x00
  2..40   fixed get-CPU-info payload (embeds command 0x0101)

Response:
  Offset  Field            Value
  0       Response marker  0xD7
  1       (reserved)       0x00
  2..40   header / routing fields
  41..56  CPU Model Name   16 bytes ASCII, padded with 0x20
```

The request and the 0xD7 / offset-41 response layout are taken from a
real capture (hi-KK/ICS-Protocol-identify "Mitsubishi Q系列PLC CPU型号
识别", TCP/5007) and the plcscan/DigitalBond `melsecq-discover.nse`
shipped alongside it, which agree byte for byte.

## CVE enrichment

The CPU model prefix names the MELSEC series, which carries NVD-verified
CVEs via `internal/cve` (`cve.ForSLMP`, a MELSEC-model-to-CVE map shared
with the `slmp` plugin): iQ-F/FX5 → CVE-2025-7731 (cleartext SLMP
credential intercept) + CVE-2024-8403 (FX5-ENET DoS); iQ-R → CVE-2020-5668
(DoS). Classic Q / L / legacy FX get the qualitative baseline only. The
match is family-level, not firmware-confirmed: pair it with the
Mitsubishi advisory.

## Proxy policy (default build)

Fail-closed. The MELSOFT service layer (program read/write, RUN/STOP,
parameter transfer) is a proprietary TLV stack that is not modelled
here, so the default-build proxy refuses the session rather than relay
bytes it cannot gate. No offensive write path ships for MELSOFT.

## Scope

- Mitsubishi Electric MELSEC CPUs reachable on their MELSOFT
  communication port, common across automotive, packaging, food &
  beverage, and semiconductor plants.
- Impact: an exposed MELSOFT endpoint is an unauthenticated
  engineering-access surface; this plugin only fingerprints it (read
  CPU info), it does not exercise the engineering services.

## Public references

- plcscan / DigitalBond `melsecq-discover.nse` (the de-facto MELSOFT
  CPU-info scanner; validates a 0xD7 response, reads the model at
  offset 42).
- Mitsubishi Electric, *QnUCPU User's Manual (Communication via
  Built-in Ethernet Port)*, SH(NA)-080811ENG, Appendix 2 "Port Numbers
  Used by Built-in Ethernet Port QCPU" (5006/5007/5008 reserved for
  MELSOFT).
- Mitsubishi Electric, *MELSEC-L Ethernet Interface Module User's Manual
  (Basic)*, SH(NA)-081105ENG, Appendix 2 (E71: 5000/5001/5002).
- Mitsubishi Electric MELSEC iQ-R / iQ-F / Q / L Series CPU Module
  User's Manual.
- ICS-CERT advisories on Mitsubishi MELSEC lacking authentication on
  the default engineering ports (multiple, 2018-onwards).
