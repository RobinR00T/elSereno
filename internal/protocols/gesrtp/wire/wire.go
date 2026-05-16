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

// ServiceLongStatus is the SRTP service code 0x21 (Read PLC Long
// Status). Sent in the canonical service-request mailbox at
// offset 42; the response's mailbox payload carries richer
// model + firmware version data than the bare CONNECTION INIT
// reply.
const ServiceLongStatus byte = 0x21

// BuildReadLongStatus builds the canonical 56-byte SRTP
// service-request mailbox carrying the Read PLC Long Status
// service code (0x21). The byte layout follows the nmap
// `gesrtp-info` NSE script (the most credible public reference)
// + the metasploit auxiliary scanner module:
//
//	byte[0]      = 0x02        // mailbox type = request
//	byte[1..41]  = zeros / reserved / packet-sequence fields
//	byte[42]     = 0x21        // service code = Read Long Status
//	byte[43]     = 0x01        // service-specific arg
//	byte[44]     = 0x03        // service-specific arg
//	byte[45]     = 0x01        // service-specific arg
//	byte[46..55] = zeros
//
// **HONEST SCOPE NOTE**: this builder follows the public nmap +
// metasploit reference. It has not been validated against a
// physical Mark VIe / RX3i / PACSystems device by the ElSereno
// team; lab confirmation is recommended before relying on the
// builder for anything beyond the v1.28 chunk-2 fingerprint
// enrichment. Operators with access to a real GE PLC are
// encouraged to capture a known-good Read Long Status response
// + share with the project so the parser tightens.
func BuildReadLongStatus() []byte {
	frame := make([]byte, MailboxLen)
	frame[0] = TypeRequest
	// bytes 1..41 stay zero (reserved per nmap reference).
	frame[42] = ServiceLongStatus
	frame[43] = 0x01
	frame[44] = 0x03
	frame[45] = 0x01
	// bytes 46..55 stay zero.
	return frame
}

// LongStatusInfo is the parsed form of a service-0x21 response
// payload. Two fields populated when present in the response
// bytes; both empty when the responder didn't carry the marker.
//
// Fields ship as plain strings rather than structured numerics
// because the response field-layout varies enough across
// firmwares (Series 90-30 vs RX3i vs PACSystems) that an exact
// schema would lock-in a single vendor's encoding. The
// scanner-grade extractor returns whatever printable-ASCII
// runs look like a model+firmware tag.
type LongStatusInfo struct {
	// Model is the first printable-ASCII run that begins with
	// one of the canonical GE PLC family prefixes (PACSystems /
	// IC693 / IC695 / IC697 / IC200 / RX3i / RX7i). Empty when
	// the response payload doesn't carry a model marker.
	Model string
	// Firmware is the first printable-ASCII run after Model
	// that matches a "V<digit>(\.\d+)+" version pattern. Empty
	// when no version-like substring follows the model. Note:
	// this is a HEURISTIC because the response layout isn't
	// authoritatively documented; consider it a best-effort
	// extraction.
	Firmware string
}

// ParseLongStatus reads a service-0x21 response mailbox + scans
// the payload for model + firmware markers. Returns an empty
// LongStatusInfo (no error) when the buffer is shorter than
// MailboxLen or doesn't carry recognisable markers.
//
// Validation surface:
//
//   - Empty buffer / short frame → empty info (no error; the
//     v1.20-chunk-3 connection-init fingerprint already gates
//     for buffer length, so this just skips silently).
//   - Buffer ≥ MailboxLen with no model marker → empty Model.
//   - Buffer with model but no version pattern → Model
//     populated, Firmware empty.
//
// Because the response field-layout varies across firmwares,
// the parser does NOT assume specific offsets. It scans the
// entire buffer for the first canonical model prefix + the
// first version-like ASCII run that follows.
func ParseLongStatus(buf []byte) LongStatusInfo {
	if len(buf) < MailboxLen {
		return LongStatusInfo{}
	}
	model := ExtractModelHint(buf)
	if model == "" {
		return LongStatusInfo{}
	}
	// Find the model substring's end + scan forward for a
	// version-like ASCII run.
	idx := indexOf(buf, []byte(model))
	if idx < 0 {
		return LongStatusInfo{Model: model}
	}
	tail := buf[idx+len(model):]
	firmware := extractFirmwareTag(tail)
	return LongStatusInfo{Model: model, Firmware: firmware}
}

// extractFirmwareTag scans the buffer for the first printable-
// ASCII run beginning with 'V' followed by a digit, then
// allowing additional digits + dots (e.g. "V5.0.40", "V12.34").
// Returns "" when no such run exists in the first 32 bytes
// after the call site.
func extractFirmwareTag(buf []byte) string {
	const scanWindow = 32
	limit := len(buf)
	if limit > scanWindow {
		limit = scanWindow
	}
	for i := 0; i < limit; i++ {
		// Need at least 'V' + digit.
		if i+2 > limit {
			break
		}
		if buf[i] != 'V' {
			continue
		}
		if !isDigit(buf[i+1]) {
			continue
		}
		// Greedy-match V + digits + dots.
		j := i + 1
		for j < limit && (isDigit(buf[j]) || buf[j] == '.') {
			j++
		}
		// Reject 1-byte runs ("V0", "V1") — too noisy.
		if j-i < 4 {
			i = j
			continue
		}
		return string(buf[i:j])
	}
	return ""
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// indexOf returns the offset of the first match of needle in
// buf, or -1 if absent. Tiny helper to avoid an additional
// `bytes` import for one call.
func indexOf(buf, needle []byte) int {
	if len(needle) == 0 || len(buf) < len(needle) {
		return -1
	}
outer:
	for i := 0; i+len(needle) <= len(buf); i++ {
		for j := 0; j < len(needle); j++ {
			if buf[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}

// gePLCFamilyPrefixes is the ordered list of canonical GE PLC
// model prefixes the extractor recognises. Order matters: the
// scanner returns the first match, so longer / more-specific
// prefixes go first.
//
// v2.30+: expanded with VersaMax-M, Mark VIe, CIMPLICITY,
// Series One/Three/Five legacy, IS220 turbine controller, and
// EFM/PAC-IO controller variants. Coverage drawn from GE
// Automation product catalogue + public nmap NSE references.
var gePLCFamilyPrefixes = []string{
	"PACSystems", // RX3i / RX7i marketing umbrella
	"VersaMax-M", // VersaMax Micro (sub-family of IC200; v2.30)
	"CIMPLICITY", // GE HMI line (rare but seen on SRTP probes; v2.30)
	"IS220",      // Mark VIe Distributed Controller (v2.30)
	"IS215",      // Mark VIe legacy controller (v2.30)
	"IC693",      // Series 90-30
	"IC695",      // RX3i
	"IC697",      // Series 90-70
	"IC200",      // VersaMax
	"RX3i",       // RX3i short form
	"RX7i",       // RX7i short form
	"MarkVIe",    // turbine controller (firmware string lacks space; v2.30)
	"Series-One", // Series One legacy (v2.30)
	"Series-90",  // Series 90 family umbrella (v2.30)
	"PAC-IO",     // PAC-IO modular controller (v2.30)
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
