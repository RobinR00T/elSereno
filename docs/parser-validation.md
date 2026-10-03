# Protocol parser validation status

elSereno parses responses from untrusted network devices. A parser is only
as trustworthy as what it was tested against: a unit test whose fixture was
hand-built to the parser's own (possibly wrong) understanding of the wire
validates nothing: it agrees with itself. Two real bugs in this codebase
(Modbus FC43/14, Omron FINS) were hidden exactly that way until a real
capture exposed them (PITF-064, PITF-065).

This table records, per response parser, whether it is validated **byte for
byte against a real capture** or only against hand-built fixtures / the spec.
"Real capture" means a test feeds bytes taken verbatim from a packet capture
of a real (or reference-stack) device.

## Validated against a real capture

| Parser | Capture source | Found |
|---|---|---|
| S7 SZL protection / identity (`s7/wire`) | ITI `s7comm_reading_plc_status.pcap` | correct |
| Modbus framing: MBAP + FC01/03/08/17 + exception (`modbus/wire`) | CISA `icsnpp-modbus` | correct |
| Modbus FC43/14 Read Device ID (`modbus/wire`) | CISA `icsnpp-modbus` | **BUG: 6-vs-7 byte header, 0 objects for real devices (PITF-064)** |
| OPC UA session establishment (`opcua/wire`) | real `SecurityPolicy#None` session | correct |
| OPC UA Browse / Read (`opcua/wire`) | CISA `icsnpp-opcua-binary` (open62541) | correct |
| ENIP ListIdentity (`enip/wire`) | CISA `icsnpp-enip` (Allen-Bradley 1756-ENBT/A) | correct |
| BACnet BVLC / I-Am / WriteProperty (`bacnet/wire`) | CISA `icsnpp-bacnet` | correct |
| DNP3 link header (`dnp3/wire`) | CISA `icsnpp-dnp3` | correct |
| IEC 60870-5-104 APCI (`iec104/wire`) | ITI `IEC104_SQ.pcapng` (real I-format frame) | correct |
| PC Worx classifier (`pcworx/wire`) | reidmefirst/PC-PCAP (Phoenix Contact ILC 191 ETH 2TX, TCP/1962) | correct (banner "ILC 191 ETH 2TX" matched) |
| MQTT CONNACK (`mqtt/wire`) | pradeesi/MQTT-Wireshark-Capture | correct (anonymous CONNECT accepted) |
| SIP response (`sip/wire`) | goffinet/sip_captures (IPP VoIP device) | correct (code / reason / Server / Allow) |
| HART-IP header (`hartip/wire`) | CISA `icsnpp-hart-ip` | correct |
| Omron FINS controller data (`finsudp/wire`) | CISA `icsnpp-omron-fins` (Omron CP1L-EL20DR-D) | **BUG: phantom SystemVersion read reserved bytes (PITF-065)** |
| MMS ACSE associate-response accept (`mms/wire`) | w3h/icsmaster `iec61850_read.pcap` | correct |

## Still fixture-only or spec-grounded

These parsers have NOT been validated against a real capture, usually because
no real capture of the specific exchange is accessible. Treat them as
assumed-correct, not proven: they are the next candidates for a real-capture
bug, and the first place to look when one is reported.

| Parser | Why not validated |
|---|---|
| SLMP / MELSEC Read CPU Model (`slmp/wire`) | no accessible pcap (ITI has none; only client libraries exist). Spec-reviewed 2026-10-03: the offsets (9-byte header, ResponseDataLength at [7:9], end code [9:11], 16-byte model [11:27], CPU type [27:29], declaredLen==20) match the MELSEC 3E READ CPU MODEL response: looks correct, still not capture-proven |
| GE-SRTP model hint (`gesrtp/wire`) | ITI pcap is a 130-byte Git LFS pointer; no real bytes. `ExtractModelHint` is a heuristic printable-run scan (not offset-based), so lower FC43-style risk |
| KNXnet/IP DescriptionResponse (`knxip/wire`) | no accessible pcap. Spec-reviewed 2026-10-03: header 6B + DIB at 6, friendly name [30:60], KNXMedium/Status/IndividualAddress offsets match the KNXnet/IP DESCRIPTION_RESPONSE DIB: looks correct, not capture-proven |
| M-Bus/TCP RSP_UD (`mbustcp/wire`) | no accessible pcap. Spec-reviewed 2026-10-03: start/L/L/start framing, total = 6+L, checksum over C..user-data, and the fixed-data-header offsets (ID [7:11], manufacturer [11:13], version [13], medium [14]) match EN 13757-3: looks correct, not capture-proven |
| MMS vendor-finding path (`mms/wire` `ExtractMMSVendorHint`) | the reachable MMS captures carry no curated vendor marker; only the no-marker path is exercised on real bytes |
| DLMS/COSEM (`dlms/wire`) | a public sample exists (bearxiong99/wireshark-dlms) but it is the **HDLC** variant (frames start `0x7e`); elSereno fingerprints DLMS over the TCP wrapper (IEC 62056-47, version `0x0001`) on 4059, which that capture does not carry. Correct for its scope, but no matching real capture |
| ProConOS runtime (`proconos/wire`, TCP/20547) | the one public "ProConOS" capture (reidmefirst/PC-PCAP) is actually PC Worx engineering traffic on 1962 (validated above as pcworx), not the 20547 runtime protocol. No runtime capture |
| ATG (Veeder-Root) | no real capture: only honeypots (GasPot, LowOctane) emulate the I20100 response, which is a fixture, not a real device |
| CoDeSys, Red Lion, TwinCat, CWMP, IAX2, XOT, AT-modem | spec-grounded / dissector-grounded; no real capture pulled into a test yet |

## Method

Captures are fetched read-only into a scratch area, parsed to extract the
exact response bytes, and those bytes are embedded in a Go test with
attribution to the source. The capture files themselves are not vendored.
The campaign that produced this table ran 2026-10-02/03; see the commit
history and PITF-064 / PITF-065 in `.context/pitfalls.md`.
