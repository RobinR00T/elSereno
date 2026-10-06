package wire

import (
	"bytes"
	"errors"
	"fmt"
)

// v2.36+ MMS service-layer extensions for the IEC 61850 mms
// plugin. Builds on the existing ACSE A-ASSOCIATE infrastructure
// (acse.go) to add:
//
//   - VendorHint extraction from the AARE response (printable
//     ASCII sequences that look like vendor / model strings).
//   - GetServerDirectory request builder + response parser.
//     Lists Logical Devices on the IED.
//
// All read-only by spec. No mutation, no control-block writes,
// no SetDataValues. Defensive default-build only.

// Curated vendor name list. Order matters: longer/more-specific
// before shorter prefixes (e.g. "SIEMENS SIPROTEC" before
// "SIEMENS"). All-uppercase because vendor strings in MMS
// responses are usually rendered in caps by stack code.
var mmsVendorMarkers = [][]byte{
	[]byte("SIEMENS SIPROTEC"),
	[]byte("SIEMENS"),
	[]byte("SCHWEITZER ENGINEERING"),
	[]byte("SEL-"),
	[]byte("ABB RELION"),
	[]byte("ABB"),
	[]byte("GE MULTILIN"),
	[]byte("GE GRID SOLUTIONS"),
	[]byte("GE"),
	[]byte("SCHNEIDER ELECTRIC"),
	[]byte("MICOM"),
	[]byte("AREVA"),
	[]byte("HITACHI ENERGY"),
	[]byte("NR ELECTRIC"),
	[]byte("RTDS"),
	[]byte("OMICRON"),
	[]byte("BECKHOFF"),
	[]byte("KALKITECH"),
	[]byte("LIBIEC61850"),
}

// MaxVendorHintLen caps how much context we surface around a
// matched vendor marker. Operators want enough to read the
// firmware version that's typically near the vendor name; not
// so much that we leak unrelated bytes.
const MaxVendorHintLen = 120

// ExtractMMSVendorHint scans `buf` (typically the AARE
// response) for any of the curated vendor markers. Returns
// the first match's surrounding text up to MaxVendorHintLen
// bytes, sanitised to printable-ASCII + dots. Empty string
// when no vendor marker is present.
//
// This is best-effort fingerprinting, it doesn't parse BER.
// We accept some false positives in exchange for working
// against vendor stacks that emit non-standard or
// extended-encoding AAREs.
func ExtractMMSVendorHint(buf []byte) string {
	upper := bytes.ToUpper(buf)
	for _, marker := range mmsVendorMarkers {
		idx := bytes.Index(upper, marker)
		if idx < 0 {
			continue
		}
		// Window the match with some leading + trailing
		// context. The vendor name itself is the high-signal
		// bit; nearby bytes often contain model + firmware.
		start := idx
		if start > 8 {
			start -= 8
		} else {
			start = 0
		}
		end := idx + len(marker) + 64
		if end > len(buf) {
			end = len(buf)
		}
		// Sanitise: keep printable ASCII (0x20-0x7E); replace
		// everything else with a dot. Bound the result.
		raw := buf[start:end]
		out := make([]byte, 0, len(raw))
		for _, b := range raw {
			if b >= 0x20 && b <= 0x7E {
				out = append(out, b)
			} else {
				out = append(out, '.')
			}
		}
		if len(out) > MaxVendorHintLen {
			out = out[:MaxVendorHintLen]
		}
		return string(out)
	}
	return ""
}

// Object classes for GetNameList (ISO 9506-2 ObjectClass).
const (
	// ObjectClassNamedVariable lists named variables.
	ObjectClassNamedVariable byte = 0
	// ObjectClassDomain lists domains, which IEC 61850-8-1 maps to
	// Logical Devices.
	ObjectClassDomain byte = 9
)

// BuildMMSGetNameListRequest returns a confirmed-RequestPDU for
// getNameList with vmd-specific scope. invokeID must be below 0x80
// (a one-octet positive INTEGER).
//
//	A0 0E                                  -- ConfirmedRequest
//	   02 01 <invokeID>                    -- invokeID
//	   A1 09                               -- service: getNameList
//	      A0 03 80 01 <class>              -- extendedObjectClass: objectClass
//	      A1 02 80 00                      -- objectScope: vmdSpecific (NULL)
//
// With invokeID 0 and class 0 it is byte for byte the getNameList the
// client sends in w3h/icsmaster iec61850_get_name_list.pcap. Until
// 2026-10-07 the scope was encoded A1 03 80 01 01: a NULL with a
// content octet, which a strict BER decoder rejects (PITF-077).
func BuildMMSGetNameListRequest(invokeID, objectClass byte) []byte {
	return []byte{
		0xA0, 0x0E,
		0x02, 0x01, invokeID,
		0xA1, 0x09,
		0xA0, 0x03, 0x80, 0x01, objectClass,
		0xA1, 0x02, 0x80, 0x00,
	}
}

// BuildMMSGetServerDirectoryRequest is IEC 61850's GetServerDirectory:
// getNameList of the domains (Logical Devices), invokeID 1. The caller
// sends it on the already-associated connection inside a P-DATA
// (WrapPData) and a COTP DT.
func BuildMMSGetServerDirectoryRequest() []byte {
	return BuildMMSGetNameListRequest(1, ObjectClassDomain)
}

// ErrNotPData is returned by UnwrapPData when the bytes are not an
// ISO 8327 Give-Tokens + Data SPDU pair carrying an ISO 8823 P-DATA.
var ErrNotPData = errors.New("mms: not a session DATA + presentation P-DATA frame")

// sessionGiveTokensData is the two-SPDU prefix (Give-Tokens, then
// Data, both with no parameters) that precedes every presentation
// P-DATA on an associated connection.
var sessionGiveTokensData = []byte{0x01, 0x00, 0x01, 0x00}

// mmsPresentationContext is the presentation context the AARQ
// defines for MMS (context 3, see BuildACSEAssociateRequestMMS).
const mmsPresentationContext = 0x03

// WrapPData wraps an MMS PDU for an associated connection: the session
// Give-Tokens + Data SPDUs and a presentation P-DATA (fully-encoded
// user data, presentation context 3, single-ASN1-type). After the
// association every MMS PDU travels like this; in the w3h/icsmaster
// captures the getNameList is 01 00 01 00 61 17 30 15 02 01 03 A0 10
// followed by the PDU. Until 2026-10-07 the probe sent the bare PDU
// after the COTP DT header, which a server cannot route (PITF-077).
func WrapPData(pdu []byte) []byte {
	inner := append([]byte{0x02, 0x01, mmsPresentationContext, 0xA0}, berLength(len(pdu))...)
	inner = append(inner, pdu...)
	pdv := append([]byte{0x30}, berLength(len(inner))...)
	pdv = append(pdv, inner...)
	out := append([]byte{}, sessionGiveTokensData...)
	out = append(out, 0x61)
	out = append(out, berLength(len(pdv))...)
	return append(out, pdv...)
}

// UnwrapPData returns the MMS PDU carried in a session Give-Tokens +
// Data and presentation P-DATA frame (the COTP DT header already
// stripped), the inverse of WrapPData. The presentation context
// identifier is not checked.
func UnwrapPData(b []byte) ([]byte, error) {
	if !bytes.HasPrefix(b, sessionGiveTokensData) {
		return nil, ErrNotPData
	}
	rest := b[len(sessionGiveTokensData):]
	for _, tag := range []byte{0x61, 0x30} {
		var ok bool
		if rest, ok = enterBER(rest, tag); !ok {
			return nil, ErrNotPData
		}
	}
	// presentation-context-identifier INTEGER
	if len(rest) < 3 || rest[0] != 0x02 || int(rest[1]) > len(rest)-2 {
		return nil, ErrNotPData
	}
	rest = rest[2+int(rest[1]):]
	pdu, ok := enterBER(rest, 0xA0)
	if !ok {
		return nil, ErrNotPData
	}
	return pdu, nil
}

// berLength encodes a BER definite length (short form below 128, long
// form with one or two octets above).
func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)} // #nosec G115 -- n < 0x80.
	case n <= 0xFF:
		return []byte{0x81, byte(n)} // #nosec G115 -- n <= 0xFF.
	default:
		return []byte{0x82, byte(n >> 8), byte(n)} // #nosec G115 -- MMS PDUs here are far below 64 KiB.
	}
}

// enterBER checks that b starts with tag and a definite length whose
// value octets are all present, and returns them; a truncated buffer
// fails rather than being clamped.
func enterBER(b []byte, tag byte) ([]byte, bool) {
	if len(b) < 2 || b[0] != tag {
		return nil, false
	}
	n, hdr := int(b[1]), 2
	switch b[1] {
	case 0x81:
		if len(b) < 3 {
			return nil, false
		}
		n, hdr = int(b[2]), 3
	case 0x82:
		if len(b) < 4 {
			return nil, false
		}
		n, hdr = int(b[2])<<8|int(b[3]), 4
	default:
		if b[1] >= 0x80 {
			return nil, false
		}
	}
	if len(b)-hdr < n {
		return nil, false
	}
	return b[hdr : hdr+n], true
}

// ErrShortGetNameListResponse is returned when the response
// is too short to even be a confirmed-response wrapper.
var ErrShortGetNameListResponse = errors.New("mms: short GetNameList response")

// ErrNotGetNameListResponse is returned when the response
// doesn't begin with a ConfirmedResponsePDU tag.
var ErrNotGetNameListResponse = errors.New("mms: not a ConfirmedResponse PDU")

// ParseMMSGetServerDirectoryResponse extracts a list of
// Logical Device names from a ConfirmedResponse PDU.
//
// The response shape (best-effort scan; we don't fully parse
// BER trees):
//
//	A1 LL                          -- ConfirmedResponse PDU
//	   02 01 01                    -- invokeID = 1
//	   A1 LL                       -- service result: getNameList
//	      A0 LL                    -- listOfIdentifier SEQUENCE
//	         1A LL <ascii bytes>   -- VisibleString per LD name
//	         1A LL <ascii bytes>
//	         ...
//	      81 01 00                 -- moreFollows = FALSE
//
// Caller has already stripped the COTP DT header (3 bytes).
//
// Returns the LD-name slice (may be empty if the IED has no
// LDs configured, which is unusual). All strings are
// validated as printable ASCII; anything non-ASCII causes
// the entry to be dropped silently.
func ParseMMSGetServerDirectoryResponse(buf []byte) ([]string, error) {
	if len(buf) < 4 {
		return nil, ErrShortGetNameListResponse
	}
	// Find the outer ConfirmedResponse PDU tag 0xA1. Some
	// stacks prepend extra OSI session/presentation header
	// bytes (we already stripped COTP DT), scan past up to
	// 64 bytes to find it.
	scan := 0
	if len(buf) > 64 {
		scan = bytes.Index(buf[:64], []byte{0xA1})
		if scan < 0 {
			return nil, ErrNotGetNameListResponse
		}
	}
	body := buf[scan:]
	if len(body) < 2 || body[0] != 0xA1 {
		return nil, ErrNotGetNameListResponse
	}
	// Find the VisibleString tag (0x1A) appearances. Each is
	// length-prefixed by a single byte (LD names are short,
	// <128 chars in practice, long-form length not
	// encountered).
	var names []string
	cursor := 2
	for cursor < len(body)-1 {
		if body[cursor] != 0x1A {
			cursor++
			continue
		}
		ln := int(body[cursor+1])
		start := cursor + 2
		end := start + ln
		if end > len(body) {
			break
		}
		nameBytes := body[start:end]
		if isPrintableASCII(nameBytes) {
			names = append(names, string(nameBytes))
		}
		cursor = end
	}
	return names, nil
}

// isPrintableASCII validates that every byte is in [0x20,
// 0x7E]. LD names per IEC 61850-6 are syntactically
// "ACSI ObjectReference" which is a subset of printable
// ASCII; this is a defensive filter.
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return len(b) > 0
}

// FormatLDList renders a slice of LD names for finding-
// payload display. Cap at 8 names + length suffix when
// there are more, so the finding stays compact.
func FormatLDList(names []string) string {
	if len(names) == 0 {
		return ""
	}
	const maxShow = 8
	if len(names) <= maxShow {
		return fmt.Sprintf("LDs: [%s]", joinWithComma(names))
	}
	return fmt.Sprintf("LDs: [%s, +%d more]", joinWithComma(names[:maxShow]), len(names)-maxShow)
}

func joinWithComma(s []string) string {
	if len(s) == 0 {
		return ""
	}
	out := s[0]
	for _, x := range s[1:] {
		out += ", " + x
	}
	return out
}
