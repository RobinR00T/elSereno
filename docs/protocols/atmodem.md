# AT modem (Hayes / GSM / EN 81-28)

Hayes-compatible modems reachable over TCP (Moxa NPort, Lantronix,
Digi PortServer) remain common in elevator remote-monitoring systems
(EN 81-28), point-of-sale networks, ATG gateways, GSM-to-Ethernet
bridges, and medical-device maintenance interfaces.

## Ports scanned

Historical defaults:
- 23 (telnet, frequently not telnet at all, just raw TCP→serial).
- 7 (echo, misconfigured serial servers).
- 2001-2032 (Moxa NPort serial port range).
- 3001 (Lantronix "TCP service 3001").
- 4001-4009 (Digi PortServer).
- 9999 (Lantronix admin).
- 10001-10004 (various serial-server defaults).

## Probe

- Drain any unsolicited banner (100 ms), then send `AT`. No `OK`
  means not an AT speaker (an info-level finding).
- On `OK`, send `ATI` and `AT+CGMI` (identify, manufacturer) and
  match the banner and both answers against the vendor dictionary
  (`atmodem/wire`): Hayes baseline plus the modem and elevator
  vendors listed there.
- Nothing else is sent: no `ATZ`, no dial (`ATD`), answer (`ATA`),
  SMS (`AT+CMGF`) or EN 81-28 vendor command.

## Proxy policy (default build)

Line by line, the proxy forwards only a read-only command
(`IsReadOnlyCommand`) and answers anything else with `ERROR\r\n`
without forwarding it. Allowed, one command per line, case and spaces
ignored: a bare `AT`; `ATI` / `ATIn`; `AT&V`; `ATSn?` (read an
S-register); `AT+<name>?` (read); `AT+<name>=?` (test); and the
identification / status commands `AT+CGMI`, `+CGMM`, `+CGMR`,
`+CGSN`, `+GMI`, `+GMM`, `+GMR`, `+GSN`, `+CIMI`, `+CCID`, `+CSQ`,
`+CLAC`. Everything else is refused: dial and answer (`ATD`, `ATA`),
commands chained on one line (`ATE0D5551234`), resets and profile
writes (`ATZ`, `AT&F`, `AT&W`), S-register writes (`ATS0=1`,
auto-answer), set commands (`AT+CFUN=0`, `AT+CPWD=...`, `AT+CLCK=...`,
SMS), `A/` and the `+++` escape.

Until 2026-10-07 the proxy refused a fixed list of prefixes (ATD, ATA,
SMS, CFUN, CPWROFF, `+++`), which chained or spaced dials and every
unlisted write got through, and it did not even answer ERROR.

## Writes (`-tags offensive`)

`offensive/dial` (see `docs/protocols/dial.md` when written) adds
`elsereno dial --number <E.164>` with the ≤3-digit hard block +
scope.blocked_numbers guard on top of the triple-confirm wrapper.

SMS send / write operations land with the offensive-build SMS
module in F6+, NOT implemented in F5.

## Scope

- Elevator remote-monitoring gateways (EN 81-28).
- Telephony / modem banks for POS, ATM, medical devices.
- Legacy GSM SCADA backends.

## Public references

- Hayes / AT command set ITU-T V.250.
- 3GPP TS 27.007 (GSM AT commands).
- EN 81-28 Alarm-system for lifts.
