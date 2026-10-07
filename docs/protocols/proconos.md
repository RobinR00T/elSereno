# KW-Software ProConOS (TCP 20547)

ProConOS is the KW-Software (Phoenix Contact) PLC runtime found in
Phoenix ILC controllers and OEM re-skins (Berghof, IPC2u, some ABB,
B&R and Lenze products).

## Probe

- Send the query of DigitalBond Redpoint's `proconos-info.nse`,
  `cc 01 00 0b 40 02 00 00 47 ee`, byte for byte the request of a real
  ProConOS session (hi-KK/ICS-Protocol-identify capture, ProConOS
  V4.2.0214).
- A reply whose byte 0 is 0xcc, or that carries a ProConOS banner
  string, confirms the runtime. No field (model, version) is parsed
  out of the reply; a reflected copy of the query is rejected
  (PITF-071).

The earlier probe sent `01 06 00 10 PROCONOS` and accepted its own
prefix back (PITF-069, fixed 2026-10-04).

## Proxy

Default build: fail-closed. No write gate exists.

## Validation

Real capture plus the NSE (`docs/parser-validation.md`). The plugin's
description still says "needs real-PLC validation": the capture
validates the exchange, not every firmware.
