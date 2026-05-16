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
// This is best-effort fingerprinting — it doesn't parse BER.
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

// BuildMMSGetServerDirectoryRequest assembles a confirmed-
// service GetServerDirectory request listing objectClass =
// domain (i.e. Logical Devices). MMS PDU is wrapped in COTP
// DT and submitted on the already-ACSE-associated connection.
//
// The Invoke-ID is hard-coded to 1 (we issue exactly one
// request per probe; no concurrent service overlap to worry
// about).
//
// Layout (ASN.1 BER, MMS PDU = ConfirmedRequestPDU tag 0xA0):
//
//	A0 LL                                  -- ConfirmedRequest
//	   02 01 01                            -- invokeID = 1
//	   A1 LL                               -- service: getNameList
//	      A0 03 80 01 09                   -- objectClass = domain (9)
//	      A1 03 80 01 01                   -- objectScope = vmd-specific
//
// MaxResultsPerRequest omitted (defaults to "no limit" per
// most IED implementations). continueAfter omitted (first
// page).
func BuildMMSGetServerDirectoryRequest() []byte {
	// Pre-compute the inner ConfirmedRequest body.
	body := []byte{
		// invokeID = INTEGER 1
		0x02, 0x01, 0x01,
		// service tag = [1] IMPLICIT getNameList = 0xA1
		0xA1, 0x0A,
		// objectClass = [0] IMPLICIT INTEGER 9 (domain)
		0xA0, 0x03, 0x80, 0x01, 0x09,
		// objectScope = [1] IMPLICIT vmdSpecific (NULL)
		0xA1, 0x03, 0x80, 0x01, 0x01,
	}
	// Wrap in ConfirmedRequestPDU = [0] CONSTRUCTED = 0xA0.
	pdu := make([]byte, 0, 2+len(body))
	// G115 guard: body is a fixed-shape PDU (≤ 24 bytes) so
	// the byte() conversion is always safe; assert defensively.
	if len(body) > 0xFF {
		// Unreachable for the current static PDU; here for
		// future extensions where body could grow.
		body = body[:0xFF]
	}
	pdu = append(pdu, 0xA0, byte(len(body))) // #nosec G115 — bounded above.
	pdu = append(pdu, body...)
	return pdu
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
	// bytes (we already stripped COTP DT) — scan past up to
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
	// <128 chars in practice — long-form length not
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
