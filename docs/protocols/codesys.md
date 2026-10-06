# CoDeSys V3 (TCP 1217)

CoDeSys V3 (formerly 3S-Smart Software Solutions, now CoDeSys
GmbH) is the runtime layer that ships with most modern soft-PLC
vendors: Wago PFC200, Beckhoff (alt-runtime), Eaton, Bosch
Rexroth, ABB AC500, Hilscher netX, Schneider M251/M258/M262,
Festo CMMP/CMMS, plus dozens of smaller automation-component
vendors. The CoDeSys Gateway-Server binds TCP/1217 by default;
some installations also expose 11740 (newer) or 1200 (V2 legacy).

## Probe

> **STATUS (PITF-068, magic corrected 2026-10-04):** the recognition magic is
> now the real Block Driver value `0xE8170100` (little-endian on the wire:
> `00 01 17 e8`). Earlier builds used `0xCD 0xCD 0xCD 0xCD`, the MSVC debug
> "uninitialised heap" fill pattern, almost certainly read off an
> uninitialised buffer during reverse-engineering. The correct value is
> confirmed by three independent sources: Tenable's CODESYS gateway V3 PoC
> (`pack('<II', 0xe8170100, len)` on send, `magic != 0xe8170100` on recv), the
> Kaspersky ICS-CERT CODESYS Runtime paper, and a real capture (`cds3.pcapng`:
> every frame, both directions, opens with `00 01 17 e8`).
>
> **Still deferred:** a complete eliciting probe. `BuildHello` sends only the
> 4-byte magic, which is not a full frame, so a real gateway does not reply to
> it; the Tenable channel-open PDU is validated only against DWRCS.exe on 11743,
> and the capture's first client PDU on 11740 embeds an endpoint IP, so no
> host-independent probe for the canonical 1217 gateway is confirmed, and
> shipping one would change the tool's active on-wire posture. The banner path
> is the default-build signal. Note the legitimate `0x55cd` below is the
> services-layer protocol id, a different field, not this magic.

- Send the 4-byte Block Driver magic (`0xE8170100`, LE on the wire
  `00 01 17 e8`). This is the real magic prefix, not a complete eliciting
  probe (see the status note above), so default-build identification rests on
  the banner path.
- Classify the response by either:
  - **BlockDriver magic echo**: the server's first 4 bytes
    match the magic, indicating a real CoDeSys V3
    handshake, OR
  - **Banner substring match**: the response contains one of
    the canonical CoDeSys banner strings:
    `CoDeSys`, `CODESYS`, `3S-Smart`, `3S-CoDeSys`,
    `CmpHostname`, `CmpAppBP`, `CmpRuntime`. Some gateways
    prefix a plain-text greeting before the binary handshake.

## Wire layout (BlockDriver)

```
Offset  Field   Size  Description
0..3    Magic   4     0xE8170100 (LE on the wire: 00 01 17 e8)
4..7    Length  4     LE: total frame length, INCLUDING this 8-byte header
8+      PDU     …     datagram / channel / service layers (Layer-3 / 4 / 7)
```

The full CoDeSys V3 service-request layer is out of scope for
this fingerprint, we treat all bytes after the 4-byte magic
as opaque. Future offensive plugins would decode the layered
"Layer-3 / Layer-4 / Layer-7" APDU stack to drive specific
service requests.

## Active probe (opt-in: `codesys-active`)

The default `codesys` plugin is banner + magic-recognition only: a bare
4-byte magic does not elicit a gateway reply, so a gateway that sends no
plaintext banner is missed. The opt-in `codesys-active` plugin closes
that gap by sending the minimal **channel-open PDU** the gateway does
answer, then confirming CoDeSys by the Block-Driver-framed reply
(`00 01 17 e8` magic). It is read-only: it opens a channel to read the
reply and issues no service request that reads, writes, or changes
controller state. Its findings carry the protocol name `codesys-active`
(not `codesys`), so they stay distinguishable in every output.

Both CoDeSys probes reject a reply that merely echoes their own probe
before classifying it (PITF-071): the magic opens every frame in both
directions, so a reflecting service would otherwise look like a gateway.

It is kept out of the default read-only sweep (DefaultPort 0, OptIn), so
a normal scan never opens a gateway channel. Run it explicitly:

```sh
elsereno fingerprint probe --plugin codesys-active --target plc:1217
```

The channel-open frame (block driver + L3 datagram + L4 channel-open
meta, all addressing zeroed so it is host-independent) is ported byte for
byte from the Tenable CODESYS gateway V3 PoC and validated against that
reference (`wire/channel_test.go`, fixed client id). It has NOT been
exercised against a live 1217 gateway, so the reply is classified by the
capture-confirmed Block Driver magic rather than a presumed reply shape.

## Proxy policy (default build)

Fail-closed. CoDeSys V3 is a proprietary tag-length-value
protocol whose deeper layers (Layer-3 / Layer-4 / Layer-7) are
not implemented. The default-build proxy refuses sessions
immediately rather than relay bytes that may or may not be
valid CoDeSys frames, defence-in-depth fail-closed pattern.

## Writes (`-tags offensive`)

Shipped. The write-gated TCP proxy lives in
`offensive/write/codesys` (ports 1217 and 11740). Reads (handshake,
status, variable reads) always pass; a mutating L7 command is
admitted only when its `(service, cmd)` pair is allowlisted.

```sh
# 1) Mint the session confirm-token (ADR-039 triple-confirm):
elsereno-offensive write codesys proxy-dry-run \
  --target plc.internal:1217 \
  --codesys-command 0x02:0x10 \    # CmpApp/Start
  --codesys-command 0x02:0x11 \    # CmpApp/Stop
  --codesys-command 0x09:0x06 \    # CmpIecVarAccess/WriteVars
  --vault-passphrase-file ~/.elsereno/dev.pp

# 2) Run the gated proxy (TCP/1217) with the triple-confirm fence:
elsereno-offensive proxy listen --plugin codesys \
  --listen 127.0.0.1:1217 --target plc.internal:1217 \
  --codesys-command 0x02:0x10 --codesys-command 0x02:0x11 \
  --codesys-command 0x09:0x06 \
  --accept-writes --confirm-target plc.internal:1217 \
  --confirm-token <token-from-dry-run> \
  --vault-passphrase-file ~/.elsereno/dev.pp
```

Flag: `--codesys-command SERVICE:CMD` (byte pair, decimal or `0x..`,
repeatable; e.g. `0x02:0x10` CmpApp/Start, `0x02:0x11` CmpApp/Stop,
`0x09:0x06` CmpIecVarAccess/WriteVars).

**Classifier design (and why it differs from FINS/SLMP/GE-SRTP)**:
CoDeSys v3 has no transport-layer length delimiter a gate can trust
(the reference dissector locates layers by byte-magic scan, not by
reading lengths), so the handler does **not** parse the L3/L4
transport (a length we misread would be a bypass). It buffers the
reassembled client to server stream and, via `wire.ScanL7`, locates
**every** L7 service header (protocol_id magic `0x55cd` / `0x7557`)
and classifies each `(service_id, cmd_id)`.

**Refusal semantics**: **fail-closed**. The stream is forwarded only
while every located command is a read or an allowlisted write; any
unknown command, non-allowlisted write, or truncated L7 header at
EOF **closes the connection**. This is deliberately conservative (it
can refuse an exotic-but-benign frame) but cannot be desynchronised
into forwarding a hidden write: a real write header must carry the
magic to be parsed by the PLC, so it is always located and
classified. The scanner comes from `internal/protocols/codesys/wire`
(reference Wireshark dissector fridgebuyer/codesys3-dissector).
Triple-confirm + audit-chain emission per ADR-039.

## Scope

- Soft-PLC runtimes across European + global automation
  vendors (Wago, Beckhoff, Eaton, Schneider M251/M258/M262,
  Bosch Rexroth, ABB AC500, Hilscher netX, Festo CMMP/CMMS).
- Some HMI gateways (CoDeSys Visualization Web Server) bridge
  CoDeSys to HTTP/8080.
- Impact: a writeable CoDeSys endpoint can replace the running
  application (CmpAppBP write), add operating-system users
  (CmpUserMgr), or stop the runtime entirely. Affects every
  ICSA advisory on the CoDeSys family.

## Public references

- ICS-CERT advisories ICSA-12-242-01, ICSA-19-080-01,
  ICSA-21-014-04, multiple CVEs on authentication bypass +
  remote code execution paths.
- nmap NSE script `codesys-info` (community).
- Open-source clients: libcodesys-py, codesys-rs.
- 3S CoDeSys Online Help, protocol reference (registration
  required).
