# Protocol support

ElSereno registers **35 plugins** in the default build: 31 protocol
plugins, the `banner` catch-all, and three opt-in, read-only probes
(`s7-exposure`, `opcua-exposure`, `codesys-active`) that run only when
named. `elsereno plugins list` prints the set on your binary. Every
default-build proxy is read-only (write-ban, deny-all or fail-closed);
writes need `-tags offensive` and the ADR-039 triple-confirm wrapper,
and `proxy listen` serves the 18 protocols in **bold**. Seven more
(atg, dlms, fox, hartip, iec104, knxip, mbustcp) have a gated package
under `offensive/write/` that no command wires yet (open decision in
TODO-vNext).

See also [`../exposure-auditing.md`](../exposure-auditing.md) for the
read-only deep-exposure probes and [`../parser-validation.md`](../parser-validation.md)
for which probes are validated byte for byte against real captures or
reference tools (vs spec-grounded). This table was rebuilt from the
code on 2026-10-07; several rows had described probes the code never
sent.

| Protocol | Port | Probe (what is sent) | Proxy, default build |
|----------|------|----------------------|----------------------|
| [**Modbus/TCP**](modbus.md) | 502 | FC 1 Read Coils + opportunistic FC 43/14 | write-ban (IllegalFunction) |
| [**S7comm**](s7.md) | 102 | TPKT/COTP Connection Request (TSAP 0x0100/0x0102) | write-ban (AckData errClass 0x85) |
| [**EtherNet/IP**](enip.md) | 44818 | ListIdentity (encapsulation 0x63) | write-ban (status 0x0001) |
| [**BACnet/IP**](bacnet.md) | 47808/udp | Who-Is, original-unicast, hop count 255 | fail-closed (UDP) |
| [**DNP3**](dnp3.md) | 20000 | Request Link Status to addresses 0..100 (valid CRCs) | user data and resets refused (FC 15 Not Supported) |
| [IEC 60870-5-104](iec104.md) | 2404 | TESTFR act | I-frames refused (STOPDT act) |
| [HART-IP](hartip.md) | 5094 | Session Initiate (matches a real client) | TokenPassPDU refused (status 0x04) |
| [Niagara Fox](fox.md) | 1911 | client hello (nmap fox-info) | deny-all (`fox a 0 -1 fox denied`) |
| [ATG Veeder-Root](atg.md) | 10001 | `\x01I20100\n` | non-`I` commands refused (`9999FF1B`) |
| [**OPC UA**](opcua.md) | 4840 | HEL Hello | deny-all (one ERR, then drop) |
| [**OPC UA HTTPS**](opcuahttps.md) | 4843 | GetEndpoints POST to `/`, fallback POST `/discovery` | deny-all |
| [XOT](xot.md) | 1998 | X.25 Call Request | plain pass-through |
| [AT modem](atmodem.md) | 9999 | `AT`, then `ATI` + `AT+CGMI` | forbidden prefixes (ATD, ATA, ...) answered `ERROR` |
| [**SIP**](sip.md) | 5060/udp | OPTIONS (UDP only) | deny-all (`403 Forbidden`) |
| [**IAX2**](iax2.md) | 4569/udp | NEW (bare full frame) | deny-all (silent) |
| [**pbxhttp**](pbxhttp.md) | 443 | HTTPS `GET /` | deny-all (`403 Forbidden`) |
| [**CWMP / TR-069**](cwmp.md) | 7547 | `GET /` (never an Inform) | deny-all (`403 Forbidden`) |
| [**Omron FINS**](finsudp.md) | 9600/udp | CONTROLLER DATA READ (MRC 0x05 SRC 0x01) | fail-closed (UDP) |
| [**MELSEC SLMP**](slmp.md) | 5007 | READ CPU MODEL NAME (0x0101 / 0x0000) | write-ban (end code 0xC059) |
| [MELSOFT](melsoft.md) | 5007 | get-CPU-info request (0x57, embeds 0x0101) | fail-closed |
| [**GE-SRTP**](gesrtp.md) | 18245 | all-zero CONNECTION INIT, then 0x21 Read Long Status | write-ban |
| [KNXnet/IP](knxip.md) | 3671/udp | DESCRIPTION_REQUEST (0x0203) | fail-closed (UDP) |
| [M-Bus over TCP](mbustcp.md) | 10001 | REQ_UD2 to 0xFE | write-ban (ACK 0xE5) |
| [DLMS/COSEM](dlms.md) | 4059 | wrapper-framed AARQ (= Gurux public client) | write-ban (AARE rejected-permanent) |
| [**IEC 61850 MMS**](mms.md) | 102 | COTP CR, AARQ (= real client), GetNameList in P-DATA | fail-closed |
| [**PC Worx**](pcworx.md) | 1962 | nmap pcworx-info `init_comms` | fail-closed |
| [ProConOS](proconos.md) | 20547 | Redpoint proconos-info query | fail-closed |
| [TwinCAT ADS](twincat.md) | 48898 | AMS ReadDeviceInfo, NetID 0.0.0.0.0.0 | fail-closed |
| [**CoDeSys V3**](codesys.md) | 1217 | 4-byte Block Driver magic; banner match | fail-closed |
| [CoDeSys V3 active](codesys.md) | none (opt-in; use 1217) | channel-open PDU (Tenable PoC) | fail-closed |
| [**Red Lion CR3**](redlion.md) | 789 | manufacturer + model register reads (cr3-fingerprint.nse) | fail-closed |
| [MQTT](mqtt.md) | 1883 (8883 TLS) | anonymous CONNECT, wildcard SUBSCRIBE | deny-all |
| [Banner](banner.md) | any | reads what the port sends | none |

## Proxy default-build policy

Three postures, per the last column above:

- **Write-ban.** Frames the wire classifier labels CategoryRead are
  forwarded byte for byte; any other frame gets a protocol-native
  refusal and never reaches upstream.
- **Deny-all.** Nothing is forwarded; the client gets one native
  refusal (an HTTP or SIP 403, a UA ERR, a Fox denial) or silence.
- **Fail-closed.** The proxy refuses the session outright (proprietary
  stacks without a read classifier, and the UDP protocols, which the
  TCP proxy framework does not relay).
- **Wire-layer enforcement.** A misconfigured scope.yaml, env var,
  CLI flag, or plug-in chain cannot route a write to upstream in the
  default build (ADR-040). The only way to issue a write is to compile
  with `-tags offensive` AND pass the triple-confirm flags AND unlock
  the vault.

## Offensive writes (-tags offensive)

See [ADR-039](../../.context/decisions/039-offensive-architecture-triple-confirm.md)
for the triple-confirm contract. Each mutating operation passes
through `offensive/confirm.Authorize(ctx, Mutation, Confirm) error`
which requires **all three**: `--accept-writes`, `--confirm-target
<target>`, and `--confirm-token <hex>` derived via HMAC-SHA256 from
the vault master key.

Operators run the target tool twice, once with `--dry-run` to mint
the expected token, once with `--confirm-token <value>` to fire.

## Deeper protocol notes

The `.context/protocols/` directory holds the engineering-level notes
(wire format, fingerprint rationale, score factors) used during
implementation. The files in `docs/protocols/` are operator-facing
summaries with the details you need to run ElSereno against a target.
