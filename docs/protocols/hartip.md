# HART-IP (port 5094)

HART-IP (FCG TS20085) carries HART field-device traffic over TCP.
Deployed on plant-control networks for pressure / flow / level /
temperature instrumentation gateways.

## Probe

- Send a session-initiate request (8-byte HART-IP header with
  MsgID 0x00 + 5-byte "Primary Master + Inactivity Close" body).
- A response with MsgType 0x01 and a non-zero Status confirms
  HART-IP presence.

## Proxy policy (default build)

The 8-byte HART-IP header MsgID classifies the message:

- **CategoryRead** — SessionInitiate (0x00), SessionClose (0x01),
  KeepAlive (0x02). Forward untouched (session lifecycle must
  complete).
- **CategoryWrite** — TokenPassPDU (0x03). Carries an inner HART
  command that can be a read OR a write depending on the command
  number. The default conservatively blocks.

Refusal is a session-close response (MsgID 0x01 / MsgType 0x01)
with Status 0x04 "Unsupported command" echoing the request
sequence.

## Writes (`-tags offensive`)

HART-command-level classification (HART Cmd 1 Read Primary Variable
vs HART Cmd 45 Calibrate) lands with the offensive-build HART-IP
WriteGatedHandler in F6+.

## Scope

- HART multiplexers at plant DMZ boundaries.
- Field-device maintenance software (AMS, PRM, SmartVision).
- Impact: writes to a calibration register can misreport physical
  quantities to the control system.

## Public references

- FCG TS20085 HART-IP.
- Fieldcomm Group HART specifications (HART 7).
