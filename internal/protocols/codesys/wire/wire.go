// Package wire implements the minimum subset of CoDeSys V3
// (3S-Smart Software Solutions / now CoDeSys GmbH) needed for
// read-only fingerprinting on TCP/1217. CoDeSys V3 is the
// runtime layer that ships with most modern soft-PLC vendors —
// Wago PFC200, Beckhoff ADS gateway alternatives, Eaton, Bosch
// Rexroth, ABB AC500, Hilscher netX, Schneider M251/M258/M262,
// Festo CMMP/CMMS, and many smaller automation-component
// vendors.
//
// Public protocol documentation is sparse; this package's
// frame layout is reverse-engineered from open-source clients
// (libcodesys-py, codesys-rs) and ICS-CERT advisory captures
// (ICSA-12-242-01, ICSA-19-080-01, ICSA-21-014-04).
//
// This package implements ONLY a 4-byte BlockDriver magic
// hello + a banner-string classifier. The full CoDeSys V3
// service-request layer (tag-length-value APDUs over the
// BlockDriver framing, encrypted variants, the layered
// "Layer-3 / Layer-4 / Layer-7" protocol stack) is out of
// scope for v1.22 chunk 2 — the fingerprint is sufficient.
//
// No service-request APDUs are issued; v1.22 chunk 2 is
// read-only by design.
package wire

import (
	"bytes"
	"errors"
)

// CoDeSys V3 BlockDriver layout (reverse-engineered):
//
//	Offset  Field      Size  Description
//	0..3    Magic      4     0xCD 0xCD 0xCD 0xCD — BlockDriver
//	4..7    Length     4     LE: payload length (excludes header)
//	8..11   Header     4     LE: protocol header (varies by version)
//	12..15  Checksum   4     LE: header / payload checksum
//	16+     Payload    …     APDU
//
// We treat all bytes after the 4-byte magic as opaque for
// fingerprinting purposes — the server's response is classified
// either by its leading 4 bytes (BlockDriver magic echo) or by
// embedded ASCII banner strings.
const (
	// BlockDriverMagicLen is the 4-byte BlockDriver magic
	// prefix length.
	BlockDriverMagicLen = 4
)

// BlockDriverMagic is the canonical 4-byte BlockDriver magic
// prefix that opens every CoDeSys V3 BlockDriver frame.
var BlockDriverMagic = []byte{0xCD, 0xCD, 0xCD, 0xCD}

// CoDeSysBannerSubstrings are CoDeSys server greeting / banner
// substrings. A response containing any of these is a positive
// identification even if the BlockDriver magic isn't present in
// the first 4 bytes (some gateways prefix a plain-text greeting
// before the binary handshake).
var CoDeSysBannerSubstrings = [][]byte{
	[]byte("CoDeSys"),
	[]byte("CODESYS"),
	[]byte("3S-Smart"),
	[]byte("3S-CoDeSys"),
	[]byte("CmpHostname"),
	[]byte("CmpAppBP"),
	[]byte("CmpRuntime"),
}

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface
// on the dashboard).
var (
	// ErrShortFrame means the response is shorter than the 4-
	// byte BlockDriver magic.
	ErrShortFrame = errors.New("codesys: response shorter than 4-byte BlockDriver magic")
	// ErrNotCoDeSys means the response neither leads with the
	// BlockDriver magic nor carries a CoDeSys banner substring.
	ErrNotCoDeSys = errors.New("codesys: response is not a recognisable CoDeSys frame or banner")
)

// BuildHello returns the canonical 4-byte BlockDriver hello
// (0xCD 0xCD 0xCD 0xCD). CoDeSys V3 servers reply with either:
//
//   - a BlockDriver-framed response whose first 4 bytes echo
//     the magic, or
//   - a plain-text greeting that contains one of the
//     CoDeSysBannerSubstrings.
//
// Both shapes are positive identifications.
func BuildHello() []byte {
	out := make([]byte, BlockDriverMagicLen)
	copy(out, BlockDriverMagic)
	return out
}

// Classify validates a candidate CoDeSys V3 response. On
// success it returns a short note describing which signal
// matched (BlockDriver magic vs banner substring); on failure
// the appropriate sentinel is returned.
func Classify(buf []byte) (string, error) {
	if len(buf) < BlockDriverMagicLen {
		return "", ErrShortFrame
	}
	if bytes.HasPrefix(buf, BlockDriverMagic) {
		return "BlockDriver magic", nil
	}
	for _, sub := range CoDeSysBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return "banner=" + string(sub), nil
		}
	}
	return "", ErrNotCoDeSys
}

// IsBlockDriverFrame returns true iff the buffer's first 4
// bytes match the BlockDriver magic. Useful for the "responded
// but not a real CoDeSys handshake" branch.
func IsBlockDriverFrame(buf []byte) bool {
	return len(buf) >= BlockDriverMagicLen && bytes.HasPrefix(buf, BlockDriverMagic)
}
