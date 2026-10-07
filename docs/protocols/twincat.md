# Beckhoff TwinCAT ADS (TCP 48898)

ADS over AMS/TCP is how TwinCAT engineering tools and HMIs talk to
Beckhoff runtimes (CX embedded PCs, IPCs, BC/BX terminals; TwinCAT 2
and 3).

## Probe

- One AMS/TCP frame (6-byte AMS/TCP header + 32-byte AMS header)
  carrying ADS ReadDeviceInfo (command 0x0001, state flags 0x0004) to
  AMS port 10000, with target and source AMS NetIDs 0.0.0.0.0.0.
- A response frame (state flag 0x0001) carries the ADS error, the
  version triple and the 16-byte device name, which are parsed.

## Known limit [inference]

In a real TwinCAT 3 session (the `twincat.pcapng` used on 2026-10-07)
the router answers an ADS request from an AMS NetID with no route
with a TCP RST, and replies only after the client registers over
UDP/48899. Our probe's 0.0.0.0.0.0 source has no route, so a TwinCAT 3
router that enforces routes likely resets it and the plugin reports
no confirmation. Proposal (open decision in TODO-vNext): a UDP/48899
discovery probe, which needs no route and returns NetID, host name and
TwinCAT version.

## Proxy

Default build: fail-closed. No write gate exists.

## Validation

ReadDeviceInfo response parsing validated against a real TwinCAT 2
runtime (w3h/icsmaster `beckoffiplinktc3.pcapng`).
