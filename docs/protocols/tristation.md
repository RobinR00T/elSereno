# TriStation (Triconex SIS, UDP 1502)

TriStation is the engineering protocol of Schneider Electric **Triconex**
safety instrumented systems (the Tricon controller family). A safety
instrumented system (SIS) is the independent layer that brings a process
to a safe state when it goes out of bounds: it is the last protection
between a process upset and harm to people and plant. TriStation runs over
**UDP port 1502** and has no authentication; only the controller's
physical key switch gates program changes. In 2017 the TRITON/TRISIS
malware used TriStation to reprogram a Triconex controller.

Because the target is a safety controller, the plugin is **opt-in**
(`DefaultPort 0`, `OptIn`) and never part of a default `discover`/`scan`
sweep. It runs only when named.

## Two modes

### Passive (no network)

Decode a capture offline. Nothing is sent; this is always safe.

```bash
elsereno tristation --passive --file capture.pcapng
```

It reports the controllers seen, every command by name, each command that
**changes** the safety program or run state (download, run, halt,
allocate), and any CP status the controller reported (key switch, run
state, project name and version). The repository ships a small, fully
synthetic sample (`examples/captures/tristation-demo.pcap`, addresses in
`192.0.2.0/24`, a fictional project):

```bash
elsereno tristation --passive --file examples/captures/tristation-demo.pcap
```

```
UDP datagrams: 6, TriStation frames: 6, undecodable on 1502: 0
Controller: 192.0.2.20:1502
  CONNECT REPLY                1
  CONNECT REQUEST              1
  DISCONN REQUEST              1
  Get CP status                1
  Get CP status response       1
  Run program                  1
CP status from 192.0.2.20:1502: key PROGRAM, RUNNING, project "DEMO-SIS" v1.4 (downloaded 2023-11-14T22:13:20Z)
[!] key switch in PROGRAM or REMOTE: the safety program can be changed over the network
[!] 1 command(s) that change the safety program or run state:
  2023-11-14T22:15:23Z  192.0.2.10:50000 -> 192.0.2.20:1502  Run program
  ref: NIST SP 800-82 r4 Table 16 Use of unsecure OT protocols
  ref: MITRE ATT&CK for ICS v20 T0888 Remote System Information Discovery
  ref: MITRE ATT&CK for ICS v20 T0843 Program Download
  ref: MITRE ATT&CK for ICS v20 T0858 Change Operating Mode
  ref: ISA/IEC 62443-3-3 SR 1.2 Software process and device identification and authentication
  ref: ISA/IEC 62443-3-3 SR 2.1 Authorization enforcement
  ref: ISA/IEC 62443-3-3 SR 5.1 Network segmentation
```

Both classic pcap and pcapng are read; `--json` emits the full report.

### Active (one controller)

```bash
elsereno tristation --active --target sis.example:1502
elsereno tristation --active --target sis.example:1502 --status
```

Active mode sends one TCM **CONNECT**, reads the reply, and sends
**DISCONNECT**. No TriStation command is issued. With `--status` it sends
one read-only **Get CP status** and prints the key switch position; a
switch in `PROGRAM` or `REMOTE` means the safety program can be changed
over the network. An echo guard rejects a reply that merely reflects the
probe. `--scope` is honoured.

Run active mode only against controllers you are authorised to test,
ideally during a maintenance window.

## Probe and proxy

The probe is CONNECT + DISCONNECT only; the fingerprint rests on the
CONNECT REPLY opcode, not on any command. The proxy handler is
**fail-closed**: TriStation is UDP, and relaying to a safety controller is
out of scope in every build.

## Validation

The frame layout (TCM header, TriStation header, CRC-16/ARC, the Get CP
status request and the CP status response offsets) is validated against
the public TRITON capture; see
`internal/protocols/tristation/wire/testdata/README.md` for attribution.
The capture itself is not redistributed.
