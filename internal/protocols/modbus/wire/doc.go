// Package wire implements the Modbus/TCP packet parser.
//
// Modbus/TCP frames the Modbus Application Protocol (MBAP) inside TCP:
//
//	+-----------------------+----------------+
//	|      MBAP (7 bytes)   |  PDU (FC+data) |
//	+-----------------------+----------------+
//	| TxID (2) | Proto (2)  |
//	| Length (2)| Unit (1)  |
//	+-----------+-----------+
//
// ProtocolID is always 0x0000 for classic Modbus; the parser rejects
// anything else. Length covers `Unit + PDU`; we enforce the spec cap
// of 253 PDU bytes (MODBUS Messaging on TCP/IP §3, V1.0b).
//
// Function codes are split into read (1,2,3,4,7,11,12,17,20,24) and
// write (5,6,15,16,22,23) at the Category level. The proxy uses this
// split to drop writes in read-only mode (PITF-023-adjacent: we
// enforce the safe subset in code, not at the config layer).
package wire
