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
| MMS vendor-finding path (`mms/wire` `ExtractMMSVendorHint`) | the reachable MMS captures carry no curated vendor marker; only the no-marker path is exercised on real bytes |
| KNXnet/IP, M-Bus/TCP, DLMS, CoDeSys, Red Lion, PCWorx, ProConOS, TwinCat, ATG, CWMP, SIP, IAX2, XOT, AT-modem | spec-grounded / dissector-grounded; no real capture pulled into a test yet |

## Method

Captures are fetched read-only into a scratch area, parsed to extract the
exact response bytes, and those bytes are embedded in a Go test with
attribution to the source. The capture files themselves are not vendored.
The campaign that produced this table ran 2026-10-02/03; see the commit
history and PITF-064 / PITF-065 in `.context/pitfalls.md`.
