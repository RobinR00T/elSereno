// Package wire implements the minimum subset of PC Worx (Phoenix
// Contact PC Worx Inline Controller protocol) needed for read-only
// fingerprinting on TCP/1962. PC Worx is the proprietary runtime
// protocol used by Phoenix Contact ILC-series PLCs (ILC 130 / 150 /
// 170 / 191 / 350 / 370 / 390 / AXC F families) and a number of OEM
// rebrands that ship the same firmware.
//
// The framing below is taken from, and validated against, three
// independent sources that agree byte for byte (PITF-072):
//
//   - nmap's pcworx-info.nse (DigitalBond Redpoint): its init_comms is
//     the request InitRequest sends, and it identifies PC Worx by a
//     response that "starts with 0x81".
//   - a real ILC 151 ETH session (hi-KK/ICS-Protocol-identify
//     "PCWorx协议识别.pcapng"): the client sends exactly InitRequest
//     and the PLC answers 81 01 00 14 ... (20 bytes, no banner); the
//     model string only arrives in a later 0x06 device-info reply.
//   - a real ILC 191 ETH 2TX session (reidmefirst/PC-PCAP, a Dragos
//     training capture): every response is 0x81-led.
//
// Across both captures all 25 0x81 responses carry their own total
// length, big-endian, in bytes 2..3.
//
// A previous version sent a 32-byte "01 01 00 1C IBETH01\0 + zeros"
// hello that matches neither the NSE nor any capture, and accepted a
// reply that merely started with those same four bytes: a reflected
// probe was confirmed as PC Worx, while a real PLC's first reply
// (81 01 ..., no banner) was not.
//
// No service request beyond the session init is issued; the default
// build is read-only by design.
package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// PC Worx frame layout (requests and responses):
//
//	Offset  Field    Size  Description
//	0       Kind     1     0x01 request, 0x81 response
//	1       Service  1     0x01 session init, 0x05, 0x06 device info;
//	                       a response repeats the request's service
//	2..3    Length   2     big-endian total frame length
//	4..     Body     ...   service-specific
const (
	// HelloLen is the length of InitRequest, the session-init request
	// the fingerprint sends.
	HelloLen = 26
	// ResponseKind is byte 0 of every PC Worx response (0x80 | 0x01).
	ResponseKind byte = 0x81
	// minFrameLen is the smallest valid frame (the 4-byte header).
	minFrameLen = 4
	// maxFrameLen bounds a plausible length field; the largest reply
	// in the captures is the 176-byte device-info frame.
	maxFrameLen = 8192
)

// InitRequest is the PC Worx session-init request, byte for byte the
// init_comms of nmap's pcworx-info.nse and the client's first packet
// in the real ILC 151 ETH capture:
// 01 01 00 1a 00 00 00 00 78 80 00 03 00 0c "IBETH01N0_M" 00.
var InitRequest = []byte{
	0x01, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00,
	0x78, 0x80, 0x00, 0x03, 0x00, 0x0c,
	'I', 'B', 'E', 'T', 'H', '0', '1', 'N', '0', '_', 'M', 0x00,
}

// PCWorxBannerSubstrings are response substrings that positively
// identify the upstream as PC Worx-speaking, a fallback to the 0x81
// frame check for firmwares that answer differently. None of them
// occurs in InitRequest, so a reflected request cannot match.
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
	// ErrShortFrame means the response is shorter than the 4-byte
	// PC Worx frame header.
	ErrShortFrame = errors.New("pcworx: response shorter than the 4-byte PC Worx header")
	// ErrNotPCWorx means the response is neither a PC Worx response
	// frame nor carries a known banner substring.
	ErrNotPCWorx = errors.New("pcworx: response is not a recognisable PC Worx frame or banner")
)

// BuildHello returns a copy of InitRequest, the PC Worx session-init
// request. A real PLC answers with an 0x81 response frame for service
// 0x01 (81 01 00 14 ... in the ILC 151 ETH capture).
func BuildHello() []byte {
	out := make([]byte, len(InitRequest))
	copy(out, InitRequest)
	return out
}

// IsPCWorxFrame reports whether buf starts with a PC Worx response
// frame header: byte 0 is 0x81 and the big-endian length in bytes 2..3
// is a plausible frame size. (In both captures the length equals the
// frame size exactly; equality is not required here so a reply split
// or coalesced by TCP still classifies.)
func IsPCWorxFrame(buf []byte) bool {
	if len(buf) < minFrameLen || buf[0] != ResponseKind {
		return false
	}
	n := int(binary.BigEndian.Uint16(buf[2:4]))
	return n >= minFrameLen && n <= maxFrameLen
}

// Classify validates a candidate PC Worx response. A response frame
// (IsPCWorxFrame) is the primary signal; a known banner substring is the
// fallback. On success it returns a short note (the service byte, plus
// the banner when one is present); on failure the appropriate sentinel.
func Classify(buf []byte) (string, error) {
	if len(buf) < minFrameLen {
		return "", ErrShortFrame
	}
	b := banner(buf)
	if IsPCWorxFrame(buf) {
		note := fmt.Sprintf("response service=0x%02x", buf[1])
		if b != "" {
			note += " banner=" + b
		}
		return note, nil
	}
	if b != "" {
		return "banner=" + b, nil
	}
	return "", ErrNotPCWorx
}

// banner returns the first known banner substring found in buf, cleaned
// for display, or "" when none is present.
func banner(buf []byte) string {
	for _, sub := range PCWorxBannerSubstrings {
		if bytes.Contains(buf, sub) {
			return string(bytes.TrimSpace(bytes.ReplaceAll(sub, []byte{0x00}, []byte{})))
		}
	}
	return ""
}
