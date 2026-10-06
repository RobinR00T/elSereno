# PC WORX / ProConOS (port 1962)

PC WORX is Phoenix Contact's engineering protocol for its ILC, AXC and
RFC controller families, which run the ProConOS / ProConOS eCLR
runtime. The fingerprint confirms a Phoenix Contact controller on
TCP/1962; it does not drive the deeper service-request layer.

## Probe

- Send the PC WORX session-init request (`wire.BuildHello`), byte for
  byte the `init_comms` of nmap's `pcworx-info.nse`:
  `01 01 00 1a 00 00 00 00 78 80 00 03 00 0c "IBETH01N0_M" 00`.
- Classify the reply (`wire.Classify`): a positive match is a PC WORX
  response frame (byte 0 `0x81`, the request's service byte, and a
  big-endian length in bytes 2..3), or, as a fallback, a banner substring
  (`ILC `, `Phoenix`, ...). A real PLC answers the init with
  `81 01 00 14 ...` (20 bytes, no banner); the ILC model string only
  arrives in a later device-info (`0x06`) reply, which this single-request
  probe does not ask for.
- A reply that merely reflects the probe is rejected (PITF-071).

Validated against two real captures (an ILC 151 ETH and an ILC 191 ETH
2TX) and the NSE; see PITF-072 for the earlier, wrong hello this replaced.

Capability score jumps when the target returns a PC WORX reply. The
probe is fingerprint-only and read-only: it sends one hello and reads
the reply, it issues no service-request (variable read / write /
runtime control) frames. The default-build proxy is fail-closed.

## CVE enrichment (fingerprint-confirmed)

A confirmed PC WORX device is a Phoenix Contact controller on the
ProConOS runtime, so the finding raises its `cve_exposure` factor and
records the CVE ids in its note (`internal/cve`, `cve.ForPCWorx`):

- **CVE-2022-31800** (CVSS 9.8): an unauthenticated remote attacker
  uploads malicious logic to ProConOS / eCLR controllers (no code
  signing on download) and gains full control.
- **CVE-2014-9195** (CVSS v2 10.0): ProConOS and MULTIPROG require no
  authentication for control traffic.

The match is **family-level, not firmware-confirmed**: it keys on the
runtime protocol the fingerprint proved, not on a firmware revision
(PC WORX does not report one reliably). CVE-2022-31800 is fixed in
later firmware that signs downloads, so pair it with the Phoenix
Contact advisory for the device's firmware. An unconfirmed probe keeps
the family baseline rather than claiming a CVE.

## Read-only guarantee

| Command | Writes to target? |
|---------|-------------------|
| `pcworx` fingerprint | No (one hello, reads the reply) |
| `pcworx` proxy (default build) | No (fail-closed, refuses the session) |
