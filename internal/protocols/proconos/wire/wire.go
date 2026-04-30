// Package wire implements a best-effort fingerprint for the
// KW-Software ProConOS runtime protocol on TCP/20547. ProConOS
// is the runtime kernel that ships on numerous PLC brands —
// Phoenix Contact ILC (which also speaks the higher-level
// PCWorx layer on TCP/1962), Berghof, IPC2u, ABB / B&R / Lenze
// re-skins, and a long tail of OEM rebrands.
//
// **HONEST SCOPE NOTE — needs real-PLC validation**: public
// references to the ProConOS handshake conflict. Two candidate
// hello-frame layouts are documented in the open-source
// ecosystem:
//
//  1. Some captures (older Berghof + Lenze deployments) show
//     a 4-byte prefix 0xCA 0xFE 0x00 0x00 followed by 0xCE
//     0xFA 0xDE 0xC0 (the literal "cafe…decade" structure).
//  2. Other captures (ICS-CERT 2018-15795 family + several
//     Wireshark dissectors) show a length-prefixed envelope
//     `01 06 00 10 + "PROCONOS" + zero-pad`.
//
// This package implements **the second variant** because it
// matches the dissector that ships in Wireshark's master
// branch + the metasploit/auxiliary/scanner/scada/proconos
// scanner module — both lineages an operator can verify
// independently.
//
// **The classifier is permissive on response shape** to maximise
// recall against firmware variants we haven't seen: any response
// of ≥ 4 bytes that contains the ASCII string "PROCONOS" or the
// "KW-Software" vendor marker counts as a positive
// identification, plus the prefix-echo path for compliant
// firmwares.
//
// Until at least one of {real-PLC pcap, lab confirmation against
// a Berghof/IPC2u runtime, ICS Wireshark capture against a
// known ProConOS} is available, **operators should treat
// positives at confidence ≈ 0.7** rather than the ≈ 0.95 the
// v1.20-v1.25 fingerprint plugins produce. The plugin's
// scoring reflects this with a slightly lower default
// `protocol_risk` (75 vs 80) and a lower `capability` ceiling
// (60 vs 75) than the v1.22 codesys / redlion plugins.
//
// No service-request frames are issued; the default-build proxy
// is fail-closed.
package wire

import (
	"bytes"
	"errors"
)

// Hello layout (16 bytes total):
//
//	Offset  Field             Size  Value
//	0       Length0           1     0x01
//	1       Length1           1     0x06
//	2       Length2           1     0x00
//	3       Length3           1     0x10  (16 bytes incl. header)
//	4..11   "PROCONOS"        8     ASCII
//	12..15  Pad zeros         4     0x00 0x00 0x00 0x00
const (
	// HelloLen is the canonical ProConOS hello length.
	HelloLen = 16
)

// ProConOSHelloPrefix is the 4-byte length+protocol-version
// prefix the dissector + metasploit module agree on.
var ProConOSHelloPrefix = []byte{0x01, 0x06, 0x00, 0x10}

// ProConOSToken is the 8-byte ASCII protocol identifier the
// firmware expects in the hello frame.
var ProConOSToken = []byte{'P', 'R', 'O', 'C', 'O', 'N', 'O', 'S'}

// ProConOSBannerSubstrings are response substrings that
// positively identify the upstream as ProConOS-speaking. Every
// known firmware emits at least one of these, regardless of
// hello-frame variant interpretation:
var ProConOSBannerSubstrings = [][]byte{
	[]byte("PROCONOS"),
	[]byte("ProConOS"),
	[]byte("proconos"),
	[]byte("KW-Software"),
	[]byte("KW Software"),
	[]byte("KWS-LDR"),                          // KW-Software loader marker (Berghof firmwares)
	[]byte("MultiProg"),                        // KW Multiprog runtime — same lineage
	[]byte("MULTIPROG"),                        // uppercase variant
	[]byte("\xCA\xFE\x00\x00\xCE\xFA\xDE\xC0"), // alternate-prefix firmwares
}

// Sentinel errors.
var (
	// ErrShortFrame means the response is shorter than the
	// 4-byte ProConOS hello prefix.
	ErrShortFrame = errors.New("proconos: response shorter than 4-byte ProConOS prefix")
	// ErrNotProConOS means the response neither echoes the
	// hello prefix nor carries a known banner substring.
	ErrNotProConOS = errors.New("proconos: response is not a recognisable ProConOS frame or banner")
)

// BuildHello returns the canonical 16-byte ProConOS hello frame
// (matches the Wireshark dissector + metasploit auxiliary
// scanner). The first 4 bytes are the length+version prefix
// (0x01 0x06 0x00 0x10), bytes 4..11 are "PROCONOS", bytes
// 12..15 are the zero pad.
func BuildHello() []byte {
	out := make([]byte, HelloLen)
	copy(out[0:4], ProConOSHelloPrefix)
	copy(out[4:12], ProConOSToken)
	// out[12..15] zero — canonical pad.
	return out
}

// Classify validates a candidate ProConOS response. Returns
// either a short signal description (e.g. "PROCONOS banner",
// "alt-prefix echo") on positive identification, or an
// appropriate sentinel error.
//
// The classifier is intentionally permissive — see package
// docstring's HONEST SCOPE NOTE.
func Classify(buf []byte) (string, error) {
	if len(buf) < len(ProConOSHelloPrefix) {
		return "", ErrShortFrame
	}
	if bytes.HasPrefix(buf, ProConOSHelloPrefix) {
		return "ProConOS prefix echo", nil
	}
	for _, sub := range ProConOSBannerSubstrings {
		if bytes.Contains(buf, sub) {
			// Print a clean marker name (strip non-printable
			// bytes from the alt-prefix entry).
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

// IsProConOSFrame returns true iff the buffer's first 4 bytes
// echo the ProConOS hello prefix.
func IsProConOSFrame(buf []byte) bool {
	return len(buf) >= len(ProConOSHelloPrefix) && bytes.HasPrefix(buf, ProConOSHelloPrefix)
}
