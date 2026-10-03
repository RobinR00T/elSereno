// Package wire implements a best-effort fingerprint for the
// KW-Software ProConOS runtime protocol on TCP/20547. ProConOS is
// the runtime kernel that ships on numerous PLC brands: Phoenix
// Contact ILC (which also speaks the higher-level PCWorx layer on
// TCP/1962), Berghof, IPC2u, ABB / B&R / Lenze re-skins, and a long
// tail of OEM rebrands.
//
// The fingerprint sends the canonical ProConOS enumeration request
// and checks the response signature. Both come from two independent
// reference implementations that agree byte for byte:
//
//   - DigitalBond Redpoint proconos-info.nse (the de-facto ProConOS
//     scanner): request "cc01000b4002000047ee", response first byte
//     0xcc, with name fields at offsets 13 / 45 / 78.
//   - Praetorian nerva proconos plugin: the same 10-byte request
//     {0xcc,0x01,0x00,0x0b,0x40,0x02,0x00,0x00,0x47,0xee} and
//     ResponseSignature 0xcc.
//
// A prior version sent "01 06 00 10 + PROCONOS" and expected that
// prefix echoed back; that was wrong on both the send and the recv
// side (PITF-069). The classifier still also accepts the ProConOS /
// KW-Software / MultiProg banner substrings as a fallback, to keep
// recall across firmware variants.
//
// No service-request frames are issued; the default-build proxy is
// fail-closed.
package wire

import (
	"bytes"
	"errors"
)

const (
	// RequestLen is the length of the ProConOS enumeration request.
	RequestLen = 10
	// ResponseSignature is byte 0 of a ProConOS response: a real
	// runtime answers the enumeration request with a frame whose
	// first byte is 0xcc (Redpoint and nerva agree).
	ResponseSignature byte = 0xcc
)

// ProConOSRequest is the 10-byte ProConOS enumeration request that
// both DigitalBond Redpoint and Praetorian nerva send verbatim.
var ProConOSRequest = []byte{0xcc, 0x01, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x00, 0x47, 0xee}

// ProConOSBannerSubstrings are response substrings that also
// positively identify the upstream as ProConOS-speaking, kept as a
// fallback to the 0xcc signature for recall across firmware variants.
var ProConOSBannerSubstrings = [][]byte{
	[]byte("PROCONOS"),
	[]byte("ProConOS"),
	[]byte("proconos"),
	[]byte("KW-Software"),
	[]byte("KW Software"),
	[]byte("KWS-LDR"),                          // KW-Software loader marker (Berghof firmwares)
	[]byte("MultiProg"),                        // KW MultiProg runtime, same lineage
	[]byte("MULTIPROG"),                        // uppercase variant
	[]byte("\xCA\xFE\x00\x00\xCE\xFA\xDE\xC0"), // alternate-prefix firmwares
}

// Sentinel errors.
var (
	// ErrShortFrame means the response is empty.
	ErrShortFrame = errors.New("proconos: empty response")
	// ErrNotProConOS means the response neither carries the 0xcc
	// signature nor a known banner substring.
	ErrNotProConOS = errors.New("proconos: response is not a recognisable ProConOS frame or banner")
)

// BuildHello returns the 10-byte ProConOS enumeration request. A real
// ProConOS runtime replies with a frame whose first byte is 0xcc
// (see Classify). Source: Redpoint proconos-info.nse + nerva.
func BuildHello() []byte {
	out := make([]byte, RequestLen)
	copy(out, ProConOSRequest)
	return out
}

// Classify validates a candidate ProConOS response: the 0xcc response
// signature (Redpoint + nerva), or, as a fallback, a known banner
// substring. Returns a short signal description or a sentinel error.
func Classify(buf []byte) (string, error) {
	if len(buf) < 1 {
		return "", ErrShortFrame
	}
	if buf[0] == ResponseSignature {
		return "ProConOS signature (0xcc)", nil
	}
	for _, sub := range ProConOSBannerSubstrings {
		if bytes.Contains(buf, sub) {
			// Print a clean marker name (strip non-printable bytes
			// from the alt-prefix entry).
			name := string(bytes.Map(func(r rune) rune {
				if r >= 0x20 && r < 0x7F {
					return r
				}
				return '.'
			}, sub))
			return "banner=" + name, nil
		}
	}
	return "", ErrNotProConOS
}

// IsProConOSFrame returns true iff the response carries the 0xcc
// ProConOS signature in byte 0.
func IsProConOSFrame(buf []byte) bool {
	return len(buf) >= 1 && buf[0] == ResponseSignature
}
