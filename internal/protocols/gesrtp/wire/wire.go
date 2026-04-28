// Package wire implements the minimum subset of GE-SRTP (GE
// Service Request Transfer Protocol) needed for read-only
// fingerprinting on TCP/18245. SRTP is the proprietary protocol
// for GE Fanuc / Emerson PACSystems / Series 90-30 / Series
// 90-70 / Series 90-Micro / RX3i / RX7i PLCs and many compatible
// HMIs and SCADA gateways.
//
// Public protocol documentation is sparse; this package's frame
// layout is reverse-engineered from open-source scanners
// (Rapid7's nmap NSE script gesrtp-info, Conpot's GE simulator
// fixtures, and CRP-published PROFINET/SRTP traces).
//
// This package implements ONLY the request builder + response
// classifier for the **CONNECTION INIT** mailbox — a 56-byte
// zero-filled frame with byte 0 = 0x02. The PLC replies with a
// 56-byte mailbox response whose byte 0 is 0x03 (response). The
// presence + shape of that reply is a sufficient fingerprint for
// v1.20 chunk 3; deeper service-code probing (CPU model
// identification via service 0x21) belongs to a future cycle that
// can carry test vectors against real PLCs.
package wire

import (
	"errors"
)

// SRTP mailbox layout (56 bytes):
//
//	Offset  Field                  Size  Description
//	0       Type                   1     0x02 = request, 0x03 = response
//	1       Reserved               1
//	2..3    Reserved               2
//	4..7    Reserved               4
//	8..9    Packet number          2
//	10..11  Sequence number        2
//	...     other fields           ...   service-specific
//	55      End of mailbox         1
//
// We treat all bytes other than byte 0 as opaque for v1.20 chunk
// 3. The full layout (with packet sequencing + service request
// payloads) lands when offensive write services are wired.
const (
	// MailboxLen is the canonical SRTP mailbox length (request
	// or response).
	MailboxLen = 56

	// TypeRequest marks a mailbox going from client to PLC.
	TypeRequest byte = 0x02
	// TypeResponse marks a mailbox going from PLC to client.
	TypeResponse byte = 0x03
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface on
// the dashboard).
var (
	// ErrShortFrame means the response is shorter than the
	// 56-byte mailbox length.
	ErrShortFrame = errors.New("gesrtp: response shorter than 56-byte mailbox")
	// ErrNotResponse means byte 0 of the response is not 0x03
	// (the SRTP response indicator).
	ErrNotResponse = errors.New("gesrtp: response type byte is not 0x03")
)

// BuildConnectionInit returns the canonical 56-byte SRTP
// CONNECTION INIT mailbox: byte 0 = 0x02 (request type), rest
// zero. GE PLCs and compatible HMIs respond with a 56-byte
// mailbox carrying byte 0 = 0x03; the response payload (packet
// number, sequence number, version flags) is opaque to this
// fingerprint.
//
// The frame is binary-stable: every Internet-exposed GE PLC
// that's listening on 18245 will accept this initial mailbox.
func BuildConnectionInit() []byte {
	frame := make([]byte, MailboxLen)
	frame[0] = TypeRequest
	return frame
}

// ClassifyResponse validates a candidate SRTP CONNECTION INIT
// response. On success (the response is a 56-byte mailbox with
// byte 0 = 0x03) it returns nil. On any structural failure the
// appropriate sentinel is returned.
func ClassifyResponse(buf []byte) error {
	if len(buf) < MailboxLen {
		return ErrShortFrame
	}
	if buf[0] != TypeResponse {
		return ErrNotResponse
	}
	return nil
}

// IsMailboxResponse is the sniff-only counterpart to
// ClassifyResponse: it returns true iff the buffer looks like a
// 56-byte mailbox response. Useful for the "responded but not the
// SRTP shape we wanted" branch.
func IsMailboxResponse(buf []byte) bool {
	return len(buf) >= MailboxLen && buf[0] == TypeResponse
}
