// Package wire contains the XOT / X.25 packet-level parser. The
// envelope is RFC 1613 (X.25 over TCP): a 4-byte XOT header followed
// by an X.25 packet. The X.25 payload follows ITU-T X.25 packet-level
// protocol; this parser recognises the Packet Type Identifier (PTI)
// subset relevant to fingerprinting: Call Request / Call Accepted /
// Clear Request / Clear Indication / Clear Confirmation / Reset /
// Restart / Data.
//
// The parser refuses any input that exceeds the RFC 1613 maximum X.25
// payload of 4096 bytes. Short reads return io.ErrUnexpectedEOF.
package wire
