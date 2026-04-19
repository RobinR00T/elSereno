// Package wire parses the TPKT + COTP envelope S7comm uses on port
// 102.
//
// TPKT (RFC 1006): 4 bytes: Version (1, 0x03), Reserved (1, 0x00),
// Length (uint16 BE, includes the 4-byte header).
//
// COTP (ISO 8073 class 0): LI (1) + PDU type (1) + remainder. We
// recognise CR (Connection Request 0x0E), CC (Connection Confirm
// 0x0D), and DT (Data 0x0F).
package wire
