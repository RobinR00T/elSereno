// Package wire implements the minimum subset of PCWorx (Phoenix
// Contact PCWorx Inline Controller protocol) needed for read-
// only fingerprinting on TCP/1962. PCWorx is the proprietary
// runtime protocol used by Phoenix Contact ILC-series PLCs
// (ILC 130 / 150 / 170 / 191 / 350 / 370 / 390 / AXC F families)
// and a number of OEM rebrands that ship the same firmware.
//
// Public protocol documentation is sparse; this package's hello
// frame is reverse-engineered from open-source scanners (nmap's
// `pcworx-info` NSE script + Conpot's PCWorx simulator
// fixtures) and ICS-CERT advisories (ICSA-15-160-01 / 17-201-01
// / 21-082-01).
//
// This package implements ONLY a 32-byte canonical hello frame
// + a banner / marker classifier on the response. The full
// PCWorx service-request layer (variable read / write / runtime
// control) is out of scope for v1.25 — the fingerprint is
// sufficient.
//
// No service-request frames are issued; v1.25 is read-only by
// design.
package wire

import (
	"bytes"
	"errors"
)

// PCWorx canonical hello layout (32 bytes):
//
//	Offset  Field            Size  Description
//	0..3    Magic            4     0x01 0x01 0x00 0x1C — "PCWorx hello v1"
//	4..11   IdentifyToken    8     "IBETH01\0" — interface-board
//	                                identifier required by the firmware
//	                                to accept the hello.
//	12..31  Reserved zeros   20    pad to 32 bytes.
//
// The frame is binary-stable: every Internet-exposed PCWorx-
// speaking PLC accepts this hello and replies with a 32-byte
// (or larger) frame whose payload typically embeds the firmware
// banner + ILC model string in printable ASCII.
const (
	// HelloLen is the canonical PCWorx hello length.
	HelloLen = 32
)

// PCWorxHelloPrefix is the 4-byte magic at the head of the
// canonical hello.
var PCWorxHelloPrefix = []byte{0x01, 0x01, 0x00, 0x1C}

// PCWorxIdentifyToken is the 8-byte interface-board token the
// firmware expects at offset 4..11. Trailing NUL is part of the
// token.
var PCWorxIdentifyToken = []byte{'I', 'B', 'E', 'T', 'H', '0', '1', 0x00}

// PCWorxBannerSubstrings are response substrings that positively
// identify the upstream as PCWorx-speaking. The marker list is
// pulled from the most common Phoenix Contact ILC response
// payloads observed in published scans + the Conpot simulator.
var PCWorxBannerSubstrings = [][]byte{
	[]byte("ILC "),     // most ILC families embed the model string
	[]byte("AXC F"),    // AXC F 1152 / 2152 / 3152
	[]byte("RFC "),     // RFC 460R / 470S PN PLCs
	[]byte("Phoenix"),  // vendor string
	[]byte("PHOENIX"),  // some firmwares uppercase
	[]byte("PCWorx"),   // protocol name
	[]byte("PC Worx"),  // alternate spelling
	[]byte("ProConOS"), // some ILCs report the runtime name
	[]byte("\x00FW V"), // firmware-version label "FW V…" prefixed by NUL
	[]byte("Boot V"),   // "Boot V…" bootloader version label
}

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface
// on the dashboard).
var (
	// ErrShortFrame means the response is shorter than the
	// 4-byte PCWorx hello prefix.
	ErrShortFrame = errors.New("pcworx: response shorter than 4-byte PCWorx prefix")
	// ErrNotPCWorx means the response neither echoes the
	// PCWorx hello prefix nor carries a known banner substring.
	ErrNotPCWorx = errors.New("pcworx: response is not a recognisable PCWorx frame or banner")
)

// BuildHello returns the canonical 32-byte PCWorx hello frame:
// 0x01 0x01 0x00 0x1C + "IBETH01\0" + 20 bytes of zeros.
//
// Phoenix Contact ILC PLCs reply with either:
//
//   - a frame whose first 4 bytes echo the PCWorx hello prefix,
//     or
//   - a frame whose payload contains one of the
//     PCWorxBannerSubstrings.
//
// Both shapes are positive identifications.
func BuildHello() []byte {
	out := make([]byte, HelloLen)
	copy(out[0:4], PCWorxHelloPrefix)
	copy(out[4:12], PCWorxIdentifyToken)
	// out[12..31] stay zero — the canonical pad.
	return out
}

// Classify validates a candidate PCWorx response. On success it
// returns a short note describing which signal matched (prefix
// echo vs banner substring); on failure the appropriate
// sentinel is returned.
//
// The classifier is intentionally permissive: ILC firmwares vary
// across release cycles and the response payload after the
// prefix is opaque to v1.25. Any prefix echo OR any known
// banner substring confirms PCWorx.
func Classify(buf []byte) (string, error) {
	if len(buf) < len(PCWorxHelloPrefix) {
		return "", ErrShortFrame
	}
	if bytes.HasPrefix(buf, PCWorxHelloPrefix) {
		return "PCWorx prefix echo", nil
	}
	for _, sub := range PCWorxBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return "banner=" + string(bytes.TrimSpace(bytes.ReplaceAll(sub, []byte{0x00}, []byte{}))), nil
		}
	}
	return "", ErrNotPCWorx
}

// IsPCWorxFrame returns true iff the buffer's first 4 bytes
// echo the PCWorx hello prefix. Useful for the "responded but
// not a real PCWorx handshake" branch.
func IsPCWorxFrame(buf []byte) bool {
	return len(buf) >= len(PCWorxHelloPrefix) && bytes.HasPrefix(buf, PCWorxHelloPrefix)
}
