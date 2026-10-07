// Package wire implements the minimum subset of Red Lion's
// Crimson v3 (CR3) protocol needed for read-only fingerprinting on
// TCP/789. CR3 is the protocol of Red Lion Controls' G3 / G3 Kadet /
// Graphite / FlexEdge / DA-50N HMI families (and the Sixnet-derived
// RTUs rebadged after 2017); Crimson uses it to update panels.
//
// CR3 frame (internetofallthethings/cr3-wireshark cr3.lua):
//
//	Offset  Field     Size  Description
//	0..1    Length    2     big-endian, counts the bytes after itself
//	2..3    Register  2     big-endian register number
//	4..5    Type      2     payload type
//	6..     Data      ...   type-specific (a NUL-terminated string for
//	                        the identity registers read here)
//
// The probe sends the manufacturer read of cr3-fingerprint.nse (by the
// same author, internetofallthethings/cr3-nmap), 00 04 01 2B 1B 00,
// whose reply carries "Red Lion Controls" after the 6-octet header; the
// model read 00 04 01 2A 1A 00 returns the panel model ("G310C2" in that
// README's example). praetorian-inc/nerva's crimsonv3 plugin sends the
// same two frames. A panel does not announce itself on connect.
//
// Until 2026-10-07 this package sent a made-up 3-byte zero "hello" and
// classified on banner substrings an unsolicited connect banner was
// supposed to carry; no source supports either (PITF-079). The banner
// substrings remain as a fallback. Validated against the NSE and nerva
// (reference implementations), not against a packet capture: none is
// public.
//
// No write or control frame is ever issued; the default build is
// read-only by design.
package wire

import (
	"bytes"
	"errors"
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface
// on the dashboard).
var (
	// ErrShortFrame means the response is shorter than the 4-
	// byte minimum we'll bother to classify (any reasonable
	// banner has more than 4 bytes).
	ErrShortFrame = errors.New("redlion: response shorter than 4-byte minimum")
	// ErrNotRedLion means the response doesn't carry any of the
	// canonical Red Lion banner substrings.
	ErrNotRedLion = errors.New("redlion: response is not a recognisable Red Lion banner")
)

// RedLionBannerSubstrings are the canonical banner substrings
// the classifier looks for. Order matters slightly (most
// specific first) so the matched substring in the finding note
// is informative.
var RedLionBannerSubstrings = [][]byte{
	[]byte("Red Lion Controls"),
	[]byte("Red Lion"),
	[]byte("Crimson 3"),
	[]byte("CRIMSON 3"),
	[]byte("Crimson 2"),
	[]byte("FlexEdge"),
	[]byte("Graphite"),
	[]byte("DA-50N"),
	[]byte("DA50N"),
	[]byte("G3 Kadet"),
	[]byte("G3 HMI"),
	[]byte("Sixnet"), // Sixnet RTUs (acquired 2010, rebadged Red Lion 2017)
}

// CR3 identity reads, byte for byte the probes of cr3-fingerprint.nse
// (and of nerva's crimsonv3 plugin).
var (
	// ManufacturerQuery reads register 0x012B, the manufacturer name.
	ManufacturerQuery = []byte{0x00, 0x04, 0x01, 0x2B, 0x1B, 0x00}
	// ModelQuery reads register 0x012A, the model name.
	ModelQuery = []byte{0x00, 0x04, 0x01, 0x2A, 0x1A, 0x00}
)

// HeaderLen is the CR3 header in a response: length, register, type.
const HeaderLen = 6

// ErrNotCR3String means the bytes are not a CR3 response frame
// carrying a printable string after its header.
var ErrNotCR3String = errors.New("redlion: not a CR3 response carrying a string")

// ParseStringResponse returns the string a CR3 response carries after
// its 6-octet header, without the trailing NUL, as cr3-fingerprint.nse
// reads it. The length field must match a complete frame (cr3.lua
// dissects a frame whose length + 2 equals the bytes present; more
// bytes after it are ignored, fewer are a truncated frame), and the
// string must be non-empty printable ASCII. A reflected query (a
// 6-octet frame with no data) does not qualify.
func ParseStringResponse(b []byte) (string, error) {
	if len(b) <= HeaderLen {
		return "", ErrNotCR3String
	}
	n := int(b[0])<<8 | int(b[1])
	if n+2 <= HeaderLen || n+2 > len(b) {
		return "", ErrNotCR3String
	}
	data := b[HeaderLen : n+2]
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		return "", ErrNotCR3String
	}
	for _, c := range data {
		if c < 0x20 || c > 0x7E {
			return "", ErrNotCR3String
		}
	}
	return string(data), nil
}

// Classify validates a candidate Red Lion response to
// ManufacturerQuery. A CR3 string response is the primary signal
// ("manufacturer=<name>"); a known banner substring anywhere in the
// bytes is the fallback ("banner=<substring>"). On failure the
// appropriate sentinel is returned.
func Classify(buf []byte) (string, error) {
	if len(buf) < 4 {
		return "", ErrShortFrame
	}
	if name, err := ParseStringResponse(buf); err == nil {
		return "manufacturer=" + name, nil
	}
	for _, sub := range RedLionBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return "banner=" + string(sub), nil
		}
	}
	return "", ErrNotRedLion
}

// IsRedLionBanner returns true iff the buffer contains any of
// the canonical Red Lion banner substrings.
func IsRedLionBanner(buf []byte) bool {
	for _, sub := range RedLionBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return true
		}
	}
	return false
}
