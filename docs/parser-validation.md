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
| PC Worx init + classifier (`pcworx/wire`) | reidmefirst/PC-PCAP (ILC 191 ETH 2TX, TCP/1962) + hi-KK/ICS-Protocol-identify `PCWorx协议识别.pcapng` (ILC 151 ETH) + nmap `pcworx-info.nse` | **BUG (PITF-072): the probe sent a made-up 32-byte hello (`01 01 00 1C IBETH01\0` + zeros) matching neither the NSE nor any capture, and accepted a reply starting with those same bytes ("prefix echo"): a reflected probe was confirmed while a real PLC's first reply (`81 01 00 14`, no banner) was not.** Fixed 2026-10-07: BuildHello is the NSE `init_comms`, byte-identical to the ILC 151 ETH client packet; Classify keys on the 0x81 response frame (all 25 0x81 replies across both captures carry their own big-endian length). The original banner match on the ILC 191 device-info reply still holds |
| MQTT CONNACK (`mqtt/wire`) | pradeesi/MQTT-Wireshark-Capture | correct (anonymous CONNECT accepted) |
| SIP response (`sip/wire`) | goffinet/sip_captures (IPP VoIP device) | correct (code / reason / Server / Allow) |
| DLMS/COSEM TCP-wrapper AARE (`dlms/wire`) | zeus8497/dlms-analysis (TCP-wrapper variant) | correct (wrapper + AARE tag + length) |
| HART-IP header (`hartip/wire`) | CISA `icsnpp-hart-ip` | correct |
| Omron FINS controller data (`finsudp/wire`) | CISA `icsnpp-omron-fins` (Omron CP1L-EL20DR-D) | **BUG: phantom SystemVersion read reserved bytes (PITF-065)** |
| MMS ACSE associate-response accept (`mms/wire`) | w3h/icsmaster `iec61850_read.pcap` | correct |
| GE-SRTP connection-init (`gesrtp/wire`) | Shodan device signature (automayt `GE-SRTP/Notes.txt`) + Collin Matthews' tested GE_SRTP impl | **BUG: probe sent 0x02 / expected 0x03 (the operation message) instead of the all-zero init that replies 0x01 (PITF-067)** |
| IAX2 full-frame header + NEW (`iax2/wire`) | Wireshark SampleCaptures `IAX2_incoming_call` (a real incoming NEW) | correct (F-bit, 15-bit call-number masks, BE timestamp, FrameType/Subclass offsets, and the sent-NEW shape all match the real frame; the single-packet capture carries no reply, so ACCEPT/AUTHREQ/REJECT subclass constants stay spec-grounded) |
| GOOSE IECGoosePdu (`goose`, IEC 61850-8-1, EtherType 0x88B8) | w3h/icsmaster `pcap/IEC61850/GOOSE/GOOSE.pcap` (a real GE F650 relay heartbeat) | correct (EtherType demux, the reserved APPID/Length header, and the BER-TLV APDU fields gocbRef / timeAllowedToLive / datSet / goID / stNum / sqNum / confRev / numDatSetEntries all decode byte for byte) |
| SV / Sampled Values (`goose`, IEC 61850-9-2, EtherType 0x88BA) | mgadelha/Sampled_Values `SV_Normal_Traffic.cap` (a real 9-2 publisher) | correct (802.1Q + 0x88BA demux and the savPdu BER nesting savPdu -> seqOfASDU -> ASDU: svID "4001", smpCnt, confRev, smpSynch all decode byte for byte) |
| M-Bus/TCP RSP_UD (`mbustcp/wire`) | rscada/libmbus test corpus `ACW_Itron-CYBLE-M-Bus-14.hex` (a real Itron/ACW water meter) | correct (0x68 LL 0x68 long-frame framing, length + checksum checks, and the variable-data header ID 9011523 / manufacturer "ACW" / version 20 / medium Water all decode byte for byte; M-Bus/TCP carries the same telegram as the serial bus) |
| PROFINET DCP Identify response (`profinet`, EtherType 0x8892) | w3h/icsmaster `pcap/profinet/ChangeIPUsingDCP.pcap` (a real DCP Identify response, station "X208-BORD") | correct (DCP RT header, the TLV block walk, and the flattened Identify fields NameOfStation / VendorID / DeviceID / DeviceRole / IP / Subnet / Gateway all decode byte for byte) |
| TwinCAT ADS ReadDeviceInfo (`twincat/wire`, TCP/48898) | w3h/icsmaster `pcap/beckoff/beckoffiplinktc3.pcapng` (a real TwinCAT 2 runtime, "PLC Server" v2.11.2103) | correct (AMS/TCP framing, the AMS routing header with command id + response flag + data length, and the payload error / version triple / 16-byte device name all decode byte for byte; confirms the name is 16 bytes, not 24) |
| Niagara Fox banner classifier (`fox`, TCP/1911) | w3h/icsmaster `pcap/fox/fox_info.pcap` (a real Tridium Niagara station hello) | correct (the probe classifies the real "fox a 0 -1 fox hello" + {fox.version=...} server banner as Fox; banner-substring detection, no binary frame parser) |
| ProConOS enumeration (`proconos/wire`, TCP/20547) | hi-KK/ICS-Protocol-identify `ProConOs协议识别.pcapng` (a real ProConOS V4.2.0214 / QuickMix) + DigitalBond Redpoint `proconos-info.nse` (same repo) | correct (BuildHello == the capture's request `cc01000b4002000047ee` byte for byte; Classify accepts the real 0xcc response via both the signature and the ProConOS banner fallback; confirms the PITF-069 fix on real bytes. The 2026-10-07 audit replaced a plugin-level fixture that was the request bytes themselves (an echo) with this real reply, and the probe now rejects echoes, PITF-071) |
| MELSOFT get-CPU-info (`melsoft/wire`, TCP/5007) | hi-KK/ICS-Protocol-identify `Mitsubishi Q系列PLC CPU型号识别.pcapng` (a real MELSEC Q-series CPU) + plcscan `melsecq-discover.nse` (same repo) | correct (BuildGetCPUInfo == the capture's 41-byte getcpuinfopack byte for byte; the 0xD7 response marker and the 16-byte CPU model "Q03UDECPU" at offset 41 decode byte for byte) |

## Still fixture-only or spec-grounded

These parsers have NOT been validated against a real capture, usually because
no real capture of the specific exchange is accessible. Treat them as
assumed-correct, not proven: they are the next candidates for a real-capture
bug, and the first place to look when one is reported.

| Parser | Why not validated |
|---|---|
| SLMP / MELSEC Read CPU Model (`slmp/wire`) | no accessible pcap, but CROSS-CHECKED 2026-10-03 against the official Mitsubishi SLMP Reference Manual (SH080956ENG, command 0x0101 subcommand 0x0000) and pymcprotocol (`read_cputype()` also uses 0x0101). Offsets (9-byte header, ResponseDataLength [7:9], end code [9:11], 16-byte model [11:27], CPU type [27:29], declaredLen==20) match. Consistent with spec + reference impl. A "Mitsubishi Q" capture was found 2026-10-04 (hi-KK/ICS-Protocol-identify) but it is the MELSOFT protocol on TCP/5007 (subheader 0x57/0xD7, the GX Works direct-connect frame, service "MelsoftTCP"), NOT SLMP 3E (subheader 0x50/0xD0): it does not exercise this parser, so SLMP-3E still has no public byte-capture |
| GE-SRTP model hint (`gesrtp/wire`) | the connection-init handshake is now validated (see the table above, PITF-067). `ExtractModelHint` itself is still only a heuristic printable-run scan (not offset-based), not capture-proven, but low FC43-style risk |
| KNXnet/IP DescriptionResponse (`knxip/wire`) | no accessible pcap, but CROSS-CHECKED 2026-10-03 against the knx-go reference (vapourismo/knx-go `dib.go`): DIB_DEV_INFO field order Medium[8] / Status[9] / IndividualAddress[10:12] / Serial[6] / Multicast[4] / MAC[6] / FriendlyName[30:60] and DIB type 0x01 all match. Consistent with a reference impl, still not byte-capture-proven. (The earlier 0x0204 request bug was already fixed to 0x0203 in v1.55.) |
| MMS vendor-finding path (`mms/wire` `ExtractMMSVendorHint`) | the reachable MMS captures carry no curated vendor marker; only the no-marker path is exercised on real bytes |
| ATG (Veeder-Root) | no real capture: only honeypots (GasPot, LowOctane) emulate the I20100 response, which is a fixture, not a real device |
| CoDeSys BlockDriver magic (`codesys/wire`) | **RECOGNITION CORRECTED 2026-10-04 (PITF-068): magic is now the real 0xE8170100 (LE on the wire: 00 01 17 e8), validated against THREE independent sources (Tenable gateway V3 PoC `pack('<II', 0xe8170100, len)` / `magic != 0xe8170100` on recv, the Kaspersky ICS-CERT CODESYS Runtime paper, and a real capture `cds3.pcapng` where every frame both directions opens with 00 01 17 e8). The prior 0xCDCDCDCD was the MSVC uninitialised-heap fill pattern. Classify / IsBlockDriverFrame now match real frames. ELICITING PROBE now SHIPPED OPT-IN 2026-10-04 as `codesys-active` (DefaultPort 0 / OptIn, out of the default sweep): `wire.BuildChannelOpen` sends the minimal host-independent channel-open PDU (block driver + L3 + L4 meta, all addressing zeroed), ported byte for byte from the Tenable PoC and validated against that reference (`wire/channel_test.go`, fixed client id). The reply is classified by the capture-confirmed Block Driver magic. NOT yet exercised against a live 1217 gateway (frame-validated, not live-validated). The default `codesys` plugin stays banner + magic-recognition only (read-only posture unchanged)** |
| XOT / X.25 packet layer (`xot/wire`) | no accessible pcap (bounded search of the Wireshark SampleCaptures wiki came up empty), but CROSS-CHECKED 2026-10-03 constant-by-constant against RFC 1613 (XOT envelope: version 0x0000 + BE length, 3..4096 payload) and ITU-T X.25 section 4 PTI table: CALL_REQUEST 0x0B / CALL_ACCEPTED 0x0F / CLEAR 0x13 / CLEAR_CONFIRMATION 0x17 / RR 0x01 / RNR 0x05 / REJ 0x09 / RESET 0x1B / RESET_CONFIRMATION 0x1F / INTERRUPT 0x23 / INTERRUPT_CONFIRMATION 0x27 / RESTART 0xFB / RESTART_CONFIRMATION 0xFF / DIAGNOSTIC 0xF1, plus GFI[0]>>4 / 12-bit LCN / PTI[2]. All match the spec; still not byte-capture-proven |
| CWMP / TR-069 (`cwmp`, TCP/7547) | HTTP fingerprint: keys on TR-069 / RomPager vendor markers in the HTTP response, with no bespoke binary parser, so low wire-parse risk. Spec-grounded (Broadband Forum TR-069); the `cve_exposure` note is pinned to CVE-2014-9222 (Misfortune Cookie / RomPager). No real capture pulled into a test |
| AT-modem (`atmodem`, exposed serial-to-IP) | text protocol: the result-code parser matches ITU-T V.250 (OK / ERROR / CONNECT / NO CARRIER / NO DIALTONE / BUSY / NO ANSWER / RING) and 3GPP TS 27.007 / 27.005 (`+CME ERROR` / `+CMS ERROR`), cross-checked 2026-10-03 against those specs. Text, so low parse risk. Unit-covered; no real capture pulled into a test |
| Red Lion (`redlion`, TCP/789) | banner-substring classifier (product names: Red Lion / Crimson 3 / FlexEdge / ...), no public RLN protocol doc and no accessible capture, so there is no binary frame parser to validate; low parse risk |

## Method

Captures are fetched read-only into a scratch area, parsed to extract the
exact response bytes, and those bytes are embedded in a Go test with
attribution to the source. The capture files themselves are not vendored.
The campaign that produced this table ran 2026-10-02/03; see the commit
history and PITF-064 / PITF-065 in `.context/pitfalls.md`.
