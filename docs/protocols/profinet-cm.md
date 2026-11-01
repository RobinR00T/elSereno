# PROFINET-CM (PNIO-CM, UDP 34964)

PROFINET IO devices answer a **DCE/RPC** service, the Context Manager
(PNIO-CM), on **UDP port 34964**. elSereno's `profinet-cm` plugin sends
one DCE/RPC **Endpoint Mapper (EPM) lookup** for the PNIO device interface
(`dea00001-6c97-11d1-8271-00a02442df7d`) and reads the device's
annotation: device type, order number and hardware/software revision,
enough to match the device against vendor advisories by IP, without
layer-2 access.

This complements the existing PROFINET DCP support, which is a layer-2
discovery codec (offline). PNIO-CM works across an IP boundary.

## Status: spec-grounded, not capture-validated

The request is built and parsed from DCE/RPC 1.1 (C706, connectionless
header and NDR), the p-net documentation of the PNIO UUID entities, and
the request bytes published with Nmap's `profinet-cm-lookup` script, which
elSereno's request matches **byte for byte**. No public capture of a real
device's reply was found when the plugin was written, so the response
parser checks every length and offset and reports what it could not decode
rather than guessing. The plugin is **opt-in** (`DefaultPort 0`) and its
description says "spec-grounded, not capture-validated"; treat an
identification from it as provisional until confirmed against a device.

## Run it

```bash
elsereno fingerprint probe --plugin profinet-cm --target plc.example:34964
```

A device answers from an ephemeral source port, so the probe listens on an
unconnected socket and accepts the reply from the target address only,
matched by the random DCE/RPC activity id of the request. A reply that is
not a DCE/RPC response for that activity is reported as such; a fault or
reject still proves a DCE/RPC endpoint, scored lower than a confirmed PNIO
device.

## Proxy

Fail-closed: PNIO-CM is UDP with ephemeral reply ports; the TCP proxy
framework does not relay it.

## Standards

Mapped to MITRE ATT&CK for ICS T0888 (Remote System Information Discovery)
and T0886 (Remote Services), and to ISA/IEC 62443-3-3 SR 1.2. See
`elsereno standards --standard attack-ics` and `--standard iec62443`.
