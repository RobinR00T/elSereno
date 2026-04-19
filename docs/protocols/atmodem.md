# AT modem (Hayes / GSM / EN 81-28)

Hayes-compatible modems reachable over TCP (Moxa NPort, Lantronix,
Digi PortServer) remain common in elevator remote-monitoring systems
(EN 81-28), point-of-sale networks, ATG gateways, GSM-to-Ethernet
bridges, and medical-device maintenance interfaces.

## Ports scanned

Historical defaults:
- 23 (telnet — frequently not telnet at all, just raw TCP→serial).
- 7 (echo — misconfigured serial servers).
- 2001–2032 (Moxa NPort serial port range).
- 3001 (Lantronix "TCP service 3001").
- 4001–4009 (Digi PortServer).
- 9999 (Lantronix admin).
- 10001–10004 (various serial-server defaults).

## Probe

- On connection, send `ATZ\r\n` (reset). If no response, try
  `ATE0\r\nATI\r\n` (echo-off + identify).
- Match the response against the vendor dictionary:
  Hayes baseline `OK`, plus Siemens, Nokia, Sierra, MultiTech,
  Cinterion, Telit, u-blox, Quectel, Huawei identifiers.
- Elevator monitoring: EN 81-28 command set — `ATA`, `ATD`,
  `AT+CMGF`, vendor-specific `AT^MNSPV?`.

## Proxy policy (default build)

Line-oriented state machine with a 64 KiB ceiling and `+CME`/`+CMS`
error-code extraction. The proxy enforces the list of
`ForbiddenPrefixes` at the wire layer and replies `ERROR\r\n`
without forwarding the command:

- `ATD*` — dial (voice / data). Blocked.
- `ATA` — answer incoming call.
- `AT+CMGS` / `AT+CMGW` / `AT+CMSS` / `AT+CMGD` — SMS send / store.
- `AT+CFUN` / `AT+CPWROFF` — power state.
- `+++` escape sequence (interpreted as "enter command mode").

Information queries (`ATI`, `AT+CGMI`, `AT+CIMI`, `AT+CSQ`, etc.)
forward untouched.

## Writes (`-tags offensive`)

`offensive/dial` (see `docs/protocols/dial.md` when written) adds
`elsereno dial --number <E.164>` with the ≤3-digit hard block +
scope.blocked_numbers guard on top of the triple-confirm wrapper.

SMS send / write operations land with the offensive-build SMS
module in F6+ — NOT implemented in F5.

## Scope

- Elevator remote-monitoring gateways (EN 81-28).
- Telephony / modem banks for POS, ATM, medical devices.
- Legacy GSM SCADA backends.

## Public references

- Hayes / AT command set ITU-T V.250.
- 3GPP TS 27.007 (GSM AT commands).
- EN 81-28 Alarm-system for lifts.
