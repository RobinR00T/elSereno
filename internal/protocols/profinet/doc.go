// Package profinet implements PROFINET DCP (Discovery and
// Configuration Protocol; IEC 61784-2) wire-format codec for
// the v2.39+ elsereno default build.
//
// Why a codec package, not a Probe plugin:
//
// PROFINET DCP runs directly over Ethernet (EtherType 0x8892)
// using multicast MAC 01:0E:CF:00:00:00 — L2, no IP, no TCP.
// The elsereno Probe(ctx, target) framework expects an
// (IP, port) target. Until v2.40+ ships a raw-socket scanner
// (gopacket + root cap), v2.39 delivers:
//
//  1. Wire encoder for DCP Identify / Set / Get requests.
//  2. Wire decoder for DCP responses with vendor / device /
//     station-name / IP-config extraction.
//  3. Offline-pcap decode verb so operators piping
//     `tcpdump -i eth0 ether proto 0x8892` through us can
//     inventory their PROFINET segment without writing
//     gopacket code.
//
// Frame layout (DCP over Ethernet/RT):
//
//	+---------------------------------------------------------+
//	| Ethernet header (14B)  dst=01:0E:CF:00:00:00            |
//	|                        src=<our MAC>                    |
//	|                        EtherType=0x8892                 |
//	+---------------------------------------------------------+
//	| FrameID (2B)           0xFEFE / 0xFEFF (DCP req/resp)   |
//	| ServiceID (1B)         0x05 Identify, 0x04 Get,         |
//	|                        0x03 Set, 0x06 Hello             |
//	| ServiceType (1B)       0x00 req, 0x01 resp              |
//	| XID (4B)               transaction id                   |
//	| Reserved/Delay (2B)    0x0000                           |
//	| DCPDataLength (2B)     bytes following                  |
//	+---------------------------------------------------------+
//	| Block 1 ... Block N    (TLV options)                    |
//	+---------------------------------------------------------+
//
// Block layout:
//
//	+----+--------+-------------+-----------+----------+--------+
//	|Opt | SubOpt | BlockLength | BlockInfo | DataPayload | Pad |
//	|1B  | 1B     | 2B          | 2B        | (variable)  | 0/1B|
//	+----+--------+-------------+-----------+----------+--------+
//
// Common options:
//   - 0x01 IP (suboptions 1=MAC, 2=IPParameter, 3=FullIPSuite)
//   - 0x02 Device (suboptions 1=ManufacturerSpecific,
//     2=NameOfStation, 3=DeviceID, 4=DeviceRole,
//     5=DeviceOptions, 6=AliasName, 7=DeviceInstance,
//     8=OEMDeviceID)
//   - 0x03 DHCP
//   - 0x05 Control (suboptions 1=Start, 2=Stop, 3=Signal,
//     4=Response, 5=FactoryReset, 6=ResetToFactory)
//   - 0xFF All (used in Identify requests)
//
// Defensive read-only: this package neither generates nor
// dispatches a "Set" frame in the default build. A future
// offensive cycle (per ADR-004) may add Set with the
// triple-confirm gate.
package profinet
