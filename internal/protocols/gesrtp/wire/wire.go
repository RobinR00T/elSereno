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
// This package implements:
//
//   - the request builder + response classifier for the **CONNECTION
//     INIT** mailbox — a 56-byte zero-filled frame with byte 0 = 0x02;
//     the PLC replies with a 56-byte mailbox carrying byte 0 = 0x03;
//   - **model-hint extraction** — scans the connection-init response
//     payload for printable-ASCII runs matching the canonical GE PLC
//     family patterns (IC693/IC695/IC697/IC200/RX3i/RX7i/PACSystems).
//     Many CONNECTION_INIT responses embed short model strings in the
//     payload bytes [8..55]; the extracted hint folds into the finding
//     note and lifts the gesrtp capability factor from 70 to 75 (v1.21
//     chunk 4 refinement of the v1.20 chunk 3 connection-init-only
//     signal).
//
// Service 0x21 (Read PLC Long Status) probing — a richer follow-up
// that explicitly asks the CPU for its model + firmware version —
// is left for a future cycle that can carry test vectors against
// real PLCs.
package wire

import (
	"errors"
	"strings"
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

// gePLCFamilyPrefixes is the ordered list of canonical GE PLC
// model prefixes the extractor recognises. Order matters: the
// scanner returns the first match, so longer / more-specific
// prefixes go first.
var gePLCFamilyPrefixes = []string{
	"PACSystems", // RX3i / RX7i marketing umbrella
	"IC693",      // Series 90-30
	"IC695",      // RX3i
	"IC697",      // Series 90-70
	"IC200",      // VersaMax
	"RX3i",       // RX3i short form
	"RX7i",       // RX7i short form
}

// ExtractModelHint scans the buffer for the first printable-ASCII
// run that begins with one of the canonical GE PLC family
// prefixes (IC693, IC695, IC697, IC200, PACSystems, RX3i, RX7i)
// and returns it. Only ASCII letters, digits, dashes, and
// underscores extend the run — the scanner stops at the first
// non-matching byte. If no canonical prefix is present the
// function returns "" so callers can fall back to the generic
// "SRTP mailbox response" note.
//
// Defensive against non-printable bytes and short buffers; nil /
// short input is safe (returns "").
func ExtractModelHint(buf []byte) string {
	for i := 0; i < len(buf); i++ {
		if !isModelStart(buf[i]) {
			continue
		}
		// Greedy-match a printable run.
		j := i
		for j < len(buf) && isModelByte(buf[j]) {
			j++
		}
		run := string(buf[i:j])
		// Reject runs shorter than 5 bytes (any of the canonical
		// prefixes is at least 5 chars).
		if len(run) < 5 {
			i = j
			continue
		}
		// Accept iff it begins with a canonical family prefix.
		for _, pfx := range gePLCFamilyPrefixes {
			if strings.HasPrefix(run, pfx) {
				return run
			}
		}
		i = j // skip past this run
	}
	return ""
}

// isModelStart returns true iff b can plausibly start a GE PLC
// model string (uppercase letters only — every canonical prefix
// starts with one of: I, P, R).
func isModelStart(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

// isModelByte returns true iff b is part of a GE PLC model
// string: ASCII letter, digit, dash, or underscore.
func isModelByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '-' || b == '_':
		return true
	default:
		return false
	}
}
