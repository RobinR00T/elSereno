# DNP3 (IEEE 1815, port 20000)

DNP3 (Distributed Network Protocol 3) is the predominant protocol in
North American electric utility SCADA (substations, distribution
automation) and gradually in water / wastewater.

## Probe

- Build a link-layer Request Link Status frame (Control byte 0xC9 —
  DIR=1, PRM=1, FC=9). 10 bytes fixed size, CRC is not validated
  because the probe only cares about the start-bytes `0x05 0x64`
  in the response.
- A response that starts with `0x05 0x64` signals a DNP3 outstation.

## Proxy policy (default build)

Every frame's link-layer control byte is classified:

- **CategoryRead** — PRM=0 responses, PRM=1 Test Link (FC 1), PRM=1
  Request Link Status (FC 9). Forward untouched.
- **CategoryWrite** — PRM=1 Reset Link (FC 0), Confirmed User Data
  (FC 3), Unconfirmed User Data (FC 4). The user-data frames carry
  the application layer; any application-level write (e.g. FC 2
  Write, FC 5 Direct Operate, FC 13 Cold Restart, FC 14 Warm Restart)
  travels inside FC 3/4, so the default conservatively blocks.
- **CategoryUnknown** — any primary FC outside the table. Blocked.

Refusal is a secondary FC 15 "Not Supported" frame with the source
and destination addresses swapped.

## Writes (`-tags offensive`)

Application-layer classification (distinguishing a Read Class 0
inside FC 3/4 from a Direct Operate) lands with the offensive-build
DNP3 WriteGatedHandler in F6+. The current ADR-040 matrix defers the
inner-layer parsing to that chunk; F5 writes are in-scope for
Modbus / S7 / CIP / BACnet only.

## Scope

- DNP3 outstations at power utility RTUs, DER inverters, reclosers,
  and substation IEDs.
- The link-layer probe is invisible to most deployed DNP3 RTUs and
  does not disrupt Class 0 polling.

## Public references

- IEEE Std 1815-2012.
- NIST SP 800-82r3 §DNP3.
