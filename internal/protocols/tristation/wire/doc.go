// Package wire encodes and decodes the TriStation protocol spoken by
// Schneider Electric Triconex safety controllers (SIS) on UDP/1502.
//
// A datagram is a TCM frame: opcode (1 byte), channel (1 byte), length
// of the TriStation part (uint16 LE), the TriStation part, and a CRC-16
// (CRC-16/ARC, reflected polynomial 0xA001, initial 0, uint16 LE) over
// everything before it. The TriStation part, present in COMMAND frames,
// is a 10-byte header (path/direction, connection id, command, sequence,
// two unknown bytes, checksum uint16 LE, length uint16 LE) followed by
// the command data; the checksum is the length plus the byte sum of the
// header (without the checksum) and of the data.
//
// No public specification exists. Every layout here was checked byte for
// byte against a real capture of a Triconex controller (malware_exec.pcap,
// NozomiNetworks/tricotools, see testdata/README.md), using Nozomi's
// TriStation Wireshark dissector and Triconex honeypot as reading aids.
// The package only parses and builds frames; it never opens a socket.
package wire
