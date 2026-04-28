# Protocol support

ElSereno ships **23 protocol plugins** in the default build (as
of v1.21.0, 2026-04-28). Every TCP-based plugin enforces a wire-
layer write-ban in the default build; writes land only under
`-tags offensive` and must clear the ADR-039 triple-confirm
wrapper. **7 of the 23** carry write-gated proxies with per-
object / per-path scoping (rows in **bold**).

| Protocol | Port(s) | Probe | Proxy default | Writes (offensive) |
|----------|---------|-------|---------------|--------------------|
| [**Modbus/TCP**](modbus.md) | 502 | FC 1 Read Coils + opportunistic FC 43/14 | wire write-ban (IllegalFunction) | FC 5/6/15/16/22/23 — gated per-(unit, FC, address-range) since v1.12 |
| S7comm ([s7.md](s7.md)) | 102 | TPKT/COTP Connection Request | wire write-ban (AckData errClass 0x85) | WriteVar / PLCStop / PLCRestart |
| EtherNet/IP ([enip.md](enip.md)) | 44818 | ListIdentity | SendRRData refused (status 0x0001) | SetAttributeSingle / Reset |
| [**BACnet/IP**](bacnet.md) | 47808/udp | Who-Is broadcast | fail-closed (TCP framework) | WriteProperty (svc 15) + WritePropertyMultiple (svc 16) — per-(ObjectType, Instance, PropertyID) since v1.12 / v1.13; DeleteObject (svc 11) per-(ObjectType, Instance) since v1.13; other mutating services per-service-choice only |
| DNP3 ([dnp3.md](dnp3.md)) | 20000 | link-layer Request Link Status | user-data refused (FC 15 Not Supported) | (F6+) |
| IEC 60870-5-104 ([iec104.md](iec104.md)) | 2404 | U-format TESTFR act | I-frames refused (STOPDT_act) | (F6+) |
| HART-IP ([hartip.md](hartip.md)) | 5094 | session initiate | TokenPassPDU refused (status 0x04) | (F6+) |
| Niagara Fox ([fox.md](fox.md)) | 1911, 4911 | banner scrape | fail-closed | (F6+) |
| ATG Veeder-Root ([atg.md](atg.md)) | 10001 | I20100 system status | non-`I` commands refused (`9999FF1B`) | (F6+) |
| [**OPC UA**](opcua.md) | 4840 | HEL Hello | UA ServiceFault BadUserAccessDenied | WriteRequest — per-NodeId (numeric + String/GUID/ByteString since v1.12); CallRequest per-(ObjectId, MethodId) since v1.12 |
| XOT (X.25 over TCP) ([xot.md](xot.md)) | 1998 | X.25 Call Request | pass-through with filtering | (F6+) |
| AT modem ([atmodem.md](atmodem.md)) | 23, 7, 2001-2032, 3001, 4001-4009, 9999, 10001-10004 | ATZ / ATI + vendor dictionary | ForbiddenPrefixes (ATD, ATA, CMGS/CMGW/CMSS/CMGD, CFUN, CPWROFF, `+++`) | dial (offensive only) |
| [**SIP**](sip.md) | 5060/udp+tcp | OPTIONS | SIP/2.0 405 Method Not Allowed | per-method + INVITE prefix (v1.9) + REGISTER AOR (v1.10) + From-domain (v1.12) |
| [**IAX2**](iax2.md) | 4569/udp | NEW | IAX2 HANGUP frame | per-subclass |
| [**pbxhttp**](pbxhttp.md) | 443, 80, 8088, 5001, 8443, 411 | HTTP admin probe | HTTP 405 / 403 | per-(method, path) |
| [**CWMP / TR-069**](cwmp.md) | 7547 | ACS Inform fingerprint | SOAP Fault 9001 "Request denied" | per-SOAP-RPC + per-parameter-path (v1.12) + per-firmware-URL for Download (v1.12) |
| Omron FINS ([finsudp.md](finsudp.md)) | 9600/udp | CONTROLLER DATA READ (MRC=0x05 SRC=0x01) | fail-closed (TCP framework) | (vNext — memory writes / RUN-STOP) |
| MELSEC SLMP ([slmp.md](slmp.md)) | 5007 | READ CPU MODEL NAME (cmd 0x0101 sub 0x0000) | wire write-ban (end code 0xC059) | (vNext — Batch Write / Remote RUN-STOP) |
| GE-SRTP ([gesrtp.md](gesrtp.md)) | 18245 | 56-byte CONNECTION INIT mailbox (type 0x02) | wire write-ban (mailbox response with status byte) | (vNext — write memory / RUN-STOP / program block transfer) |
| KNXnet/IP ([knxip.md](knxip.md)) | 3671/udp | DESCRIPTION_REQUEST (svc 0x0204) | fail-closed (TCP framework) | (vNext — TUNNELLING_REQUEST / DEVICE_CONFIGURATION) |
| M-Bus over TCP ([mbustcp.md](mbustcp.md)) | 10001 | REQ_UD2 to broadcast (0xFE) | wire write-ban (single-byte ACK 0xE5) | (vNext — SND_UD parameter writes / SET_BAUDRATE) |
| DLMS/COSEM ([dlms.md](dlms.md)) | 4059 | wrapper-framed AARQ (LN-no-ciphering) | wire write-ban (wrapper-framed AARE rejected-permanent) | (vNext — SET-Request / ACTION-Request remote_disconnect) |
| Banner / dictionary ([banner.md](banner.md)) | many | TCP read, vendor match | read-only | n/a |

## Proxy default-build policy

- **Reads forward.** Frames the wire classifier labels CategoryRead
  are forwarded byte-for-byte to upstream.
- **Writes refused in-band.** Non-read frames hit a protocol-native
  refusal response (see third column above) before reaching upstream.
- **Wire-layer enforcement.** A misconfigured scope.yaml, env var,
  CLI flag, or plug-in chain cannot route a write to upstream in the
  default build (ADR-040). The only way to issue a write is to compile
  with `-tags offensive` AND pass the triple-confirm flags AND unlock
  the vault.

## Offensive writes (−tags offensive)

See [ADR-039](../../.context/decisions/039-offensive-architecture-triple-confirm.md)
for the triple-confirm contract. Each mutating operation passes
through `offensive/confirm.Authorize(ctx, Mutation, Confirm) error`
which requires **all three**: `--accept-writes`, `--confirm-target
<target>`, and `--confirm-token <hex>` derived via HMAC-SHA256 from
the vault master key.

Operators run the target tool twice — once with `--dry-run` to mint
the expected token, once with `--confirm-token <value>` to fire.

## Deeper protocol notes

The `.context/protocols/` directory holds the engineering-level notes
(wire format, fingerprint rationale, score factors) used during
implementation. The files in `docs/protocols/` are operator-facing
summaries with the details you need to run ElSereno against a target.
