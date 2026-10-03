# Protocol parser validation status

elSereno parses responses from untrusted network devices. A parser is only
as trustworthy as what it was tested against: a unit test whose fixture was
hand-built to the parser's own (possibly wrong) understanding of the wire
validates nothing: it agrees with itself. Four real bugs in this codebase
(Modbus FC43/14, Omron FINS, GE-SRTP, ProConOS) were hidden exactly that way
until a real capture or a tested reference implementation exposed them
(PITF-064, PITF-065, PITF-067, PITF-069); a fifth (CoDeSys) is confirmed and
deferred (PITF-068).

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
| DLMS/COSEM TCP-wrapper AARE (`dlms/wire`) | zeus8497/dlms-analysis (TCP-wrapper variant) | correct (wrapper + AARE tag + length) |
| HART-IP header (`hartip/wire`) | CISA `icsnpp-hart-ip` | correct |
| Omron FINS controller data (`finsudp/wire`) | CISA `icsnpp-omron-fins` (Omron CP1L-EL20DR-D) | **BUG: phantom SystemVersion read reserved bytes (PITF-065)** |
| MMS ACSE associate-response accept (`mms/wire`) | w3h/icsmaster `iec61850_read.pcap` | correct |
| GE-SRTP connection-init (`gesrtp/wire`) | Shodan device signature (automayt `GE-SRTP/Notes.txt`) + Collin Matthews' tested GE_SRTP impl | **BUG: probe sent 0x02 / expected 0x03 (the operation message) instead of the all-zero init that replies 0x01 (PITF-067)** |
| IAX2 full-frame header + NEW (`iax2/wire`) | Wireshark SampleCaptures `IAX2_incoming_call` (a real incoming NEW) | correct (F-bit, 15-bit call-number masks, BE timestamp, FrameType/Subclass offsets, and the sent-NEW shape all match the real frame; the single-packet capture carries no reply, so ACCEPT/AUTHREQ/REJECT subclass constants stay spec-grounded) |

## Still fixture-only or spec-grounded

These parsers have NOT been validated against a real capture, usually because
no real capture of the specific exchange is accessible. Treat them as
assumed-correct, not proven: they are the next candidates for a real-capture
bug, and the first place to look when one is reported.

| Parser | Why not validated |
|---|---|
| SLMP / MELSEC Read CPU Model (`slmp/wire`) | no accessible pcap, but CROSS-CHECKED 2026-10-03 against the official Mitsubishi SLMP Reference Manual (SH080956ENG, command 0x0101 subcommand 0x0000) and pymcprotocol (`read_cputype()` also uses 0x0101). Offsets (9-byte header, ResponseDataLength [7:9], end code [9:11], 16-byte model [11:27], CPU type [27:29], declaredLen==20) match. Consistent with spec + reference impl, still not byte-capture-proven |
| GE-SRTP model hint (`gesrtp/wire`) | the connection-init handshake is now validated (see the table above, PITF-067). `ExtractModelHint` itself is still only a heuristic printable-run scan (not offset-based), not capture-proven, but low FC43-style risk |
| KNXnet/IP DescriptionResponse (`knxip/wire`) | no accessible pcap, but CROSS-CHECKED 2026-10-03 against the knx-go reference (vapourismo/knx-go `dib.go`): DIB_DEV_INFO field order Medium[8] / Status[9] / IndividualAddress[10:12] / Serial[6] / Multicast[4] / MAC[6] / FriendlyName[30:60] and DIB type 0x01 all match. Consistent with a reference impl, still not byte-capture-proven. (The earlier 0x0204 request bug was already fixed to 0x0203 in v1.55.) |
| M-Bus/TCP RSP_UD (`mbustcp/wire`) | no accessible pcap, but CROSS-CHECKED 2026-10-03 against libmbus (rscada/libmbus `mbus_data_variable_header`): id_bcd[4] / manufacturer[2] / version / medium after C/A/CI place ID at [7:11], manufacturer [11:13], version [13], medium [14], matching the parser and EN 13757-3. Consistent with a reference impl, still not byte-capture-proven |
| MMS vendor-finding path (`mms/wire` `ExtractMMSVendorHint`) | the reachable MMS captures carry no curated vendor marker; only the no-marker path is exercised on real bytes |
| ProConOS runtime (`proconos/wire`, TCP/20547) | no runtime pcap, but FIXED + cross-checked 2026-10-03 (PITF-069): the probe was sending `01 06 00 10 PROCONOS` and expecting that echoed back, wrong on both send and recv. Corrected to the DigitalBond Redpoint `proconos-info.nse` request `cc01000b4002000047ee` and the 0xcc response signature, which the Praetorian nerva `proconos` plugin confirms byte for byte. Response-field parsing (model at offset 45) still not capture-proven |
| ATG (Veeder-Root) | no real capture: only honeypots (GasPot, LowOctane) emulate the I20100 response, which is a fixture, not a real device |
| CoDeSys BlockDriver magic (`codesys/wire`) | **SUSPECT (PITF-068, deferred): the 0xCDCDCDCD magic is unsourced and is the MSVC uninitialised-heap fill pattern; THREE independent sources (Tenable gateway PoC + Kaspersky ICS-CERT + a real capture `cds3.pcapng`, re-parsed byte for byte on TCP/11740) put the real CODESYS block-driver magic at 0xE8170100 with an 8-byte magic[4]+size[4] header. Still not fixed: the capture's first client PDU does elicit a gateway reply but embeds endpoint addresses and session fields, so it is not a host-independent fingerprint hello, and a magic+size-only guess would repeat the PITF-067 mistake. The banner path still works** |
| Red Lion, TwinCat, CWMP, XOT, AT-modem | spec-grounded / dissector-grounded; no real capture pulled into a test yet |

## Method

Captures are fetched read-only into a scratch area, parsed to extract the
exact response bytes, and those bytes are embedded in a Go test with
attribution to the source. The capture files themselves are not vendored.
The campaign that produced this table ran 2026-10-02/03; see the commit
history and PITF-064 / PITF-065 in `.context/pitfalls.md`.
