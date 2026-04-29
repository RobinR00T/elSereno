// Package wire implements the minimum subset of the Omron FINS
// (Factory Interface Network Service) protocol needed for read-
// only fingerprinting on UDP/9600. The on-wire layout is from
// Omron CPU manual W421 (FINS Commands Reference). FINS is the
// host-link / serial / UDP / TCP framing common across CJ / CS
// / CP / NJ / NX series PLCs and shared by some HMIs.
//
// This package implements ONLY the request builder + response
// parser for **CONTROLLER DATA READ** (MRC=0x05, SRC=0x01) —
// the canonical "tell me what you are" query. The response
// carries the controller model (20 ASCII bytes) which is the
// fingerprint signal. No write or memory-read services are
// implemented; v1.20 chunk 1 is read-only by design.
package wire

import (
	"errors"
	"strings"
)

// FINS UDP frame layout (W421 §5.1):
//
//	Offset  Field  Size  Description
//	0       ICF    1     Information Control Field. 0x80 = request,
//	                     gateway-bit clear, response required.
//	                     0xC0 = response (gateway-bit set + response).
//	1       RSV    1     Reserved (always 0x00).
//	2       GCT    1     Gateway count. 0x02 = direct.
//	3       DNA    1     Destination network. 0x00 = same network.
//	4       DA1    1     Destination node. 0x00 = direct (broadcast).
//	5       DA2    1     Destination unit. 0x00 = CPU.
//	6       SNA    1     Source network. 0x00.
//	7       SA1    1     Source node. 0x01 (caller).
//	8       SA2    1     Source unit. 0x00 (no-PC origin).
//	9       SID    1     Service ID — request identifier (echoed
//	                     in response). 0x00..0xFF.
//	10      MRC    1     Main Request Code.
//	11      SRC    1     Sub Request Code.
//	12+     data   …     Command-specific.
const (
	// HeaderLen is the 10-byte FINS UDP header preceding the
	// MRC/SRC pair.
	HeaderLen = 10

	// ICFRequest sets bit 7 (gateway-bit-clear, request,
	// response-required).
	ICFRequest byte = 0x80
	// ICFResponse sets bits 7+6 (gateway-bit-set, response).
	ICFResponse byte = 0xC0

	// MRCInfoControllerData is the FINS Main Request Code for
	// Controller Data Read.
	MRCInfoControllerData byte = 0x05
	// SRCInfoControllerDataAll requests the ENTIRE controller
	// data block (model + version + system + …). 0x00 = all.
	SRCInfoControllerDataAll byte = 0x01
)

// BuildControllerDataRead crafts the 13-byte UDP datagram that
// asks a CJ/CS/CP/NJ/NX-series CPU for its full controller
// data block. The caller-supplied service-ID is echoed in the
// response; tests can pass a known value to assert correlation.
//
// Frame breakdown:
//
//	0x80 0x00 0x02 0x00 0x00 0x00 0x00 0x01 0x00 SID  ← header
//	0x05 0x01 0x00                                    ← MRC SRC area=0
func BuildControllerDataRead(sid byte) []byte {
	return []byte{
		ICFRequest, 0x00, 0x02, // ICF / RSV / GCT
		0x00, 0x00, 0x00, // DNA / DA1 / DA2
		0x00, 0x01, 0x00, // SNA / SA1 / SA2
		sid,                                             // SID
		MRCInfoControllerData, SRCInfoControllerDataAll, // MRC / SRC
		0x00, // controller-data area: 0 = all
	}
}

// ControllerData captures the parsed CONTROLLER DATA READ
// response. v1.20 chunk 1 surfaces the Model field as the
// fingerprint signal; the rest of the block is exposed but the
// plugin doesn't read it (operators can pull it via REPL when
// the framework lands).
//
// All string fields are NUL-trimmed + space-trimmed ASCII
// (FINS pads short fields with 0x20 / 0x00).
type ControllerData struct {
	Model         string // 20 bytes: e.g. "CJ2M-CPU33", "NJ501-1500"
	InternalCode  string // 20 bytes: vendor-internal version string
	SystemVersion string // 20 bytes: optional
}

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the dashboard "why did this not fingerprint"
// surface).
var (
	// ErrShortFrame means the datagram is shorter than the
	// 14-byte minimum (10 header + 2 MRC/SRC + 2 end-code).
	ErrShortFrame = errors.New("finsudp: response shorter than minimum")
	// ErrNotResponse means the ICF byte doesn't have bit 6
	// (response) set — the datagram came from a request
	// loopback, a half-finished implementation, or an
	// unrelated UDP service binding port 9600.
	ErrNotResponse = errors.New("finsudp: ICF lacks the response bit (0x40)")
	// ErrServiceMismatch means the SID we sent was not the
	// SID we got back. Not strictly a protocol error — some
	// gateways re-write the SID — but worth flagging at the
	// plugin layer for false-positive suppression.
	ErrServiceMismatch = errors.New("finsudp: SID echo mismatch")
	// ErrEndCodeNonZero means the controller responded with a
	// non-zero end code (refusal / error). The end code is at
	// bytes [12:14] of the response (after MRC/SRC).
	ErrEndCodeNonZero = errors.New("finsudp: end code non-zero (controller refused)")
)

// ParseControllerDataRead validates a CONTROLLER DATA READ
// response and extracts the model + version strings. wantSID
// is the SID echoed by the controller (matches the request).
// On any structural error the appropriate sentinel from this
// package is returned. The response shape (W421 §5.4):
//
//	Offset  Field         Size
//	0       ICF (0xC0)    1
//	1..9    rest of header  (9)
//	10      MRC (0x05)    1
//	11      SRC (0x01)    1
//	12..13  end code      2  — 0x0000 = success
//	14..33  Model         20 — ASCII, padded with 0x20
//	34..53  internal code 20 — ASCII, padded
//	54..73  system ver    20 — ASCII, padded (newer CPUs)
//
// Some CPUs return the truncated form (no system version) at
// 54 bytes total; we accept short forms gracefully.
func ParseControllerDataRead(buf []byte, wantSID byte) (ControllerData, error) {
	const minLen = HeaderLen + 4 // header + MRC + SRC + end-code
	if len(buf) < minLen {
		return ControllerData{}, ErrShortFrame
	}
	if buf[0]&0x40 == 0 {
		return ControllerData{}, ErrNotResponse
	}
	if buf[9] != wantSID {
		return ControllerData{}, ErrServiceMismatch
	}
	if buf[10] != MRCInfoControllerData || buf[11] != SRCInfoControllerDataAll {
		return ControllerData{}, ErrNotResponse
	}
	if buf[12] != 0x00 || buf[13] != 0x00 {
		return ControllerData{}, ErrEndCodeNonZero
	}
	var cd ControllerData
	if len(buf) >= 14+20 {
		cd.Model = trimASCII(buf[14 : 14+20])
	}
	if len(buf) >= 34+20 {
		cd.InternalCode = trimASCII(buf[34 : 34+20])
	}
	if len(buf) >= 54+20 {
		cd.SystemVersion = trimASCII(buf[54 : 54+20])
	}
	return cd, nil
}

// trimASCII strips trailing NULs and spaces and returns the
// remaining string. The cutset is "any of NUL/space" applied in
// a single pass — the order-dependent two-call form
// (TrimRight("\x00") then TrimRight(" ")) leaves embedded NULs
// when padding interleaves NUL and space, e.g. "MODEL\x00 \x00 "
// → after trim NUL: "MODEL\x00 \x00 " (no trailing NUL — last is
// space) → after trim space: "MODEL\x00 \x00" (still trailing NUL).
// Embedded printable bytes mid-string are preserved.
func trimASCII(b []byte) string {
	return strings.TrimRight(string(b), "\x00 ")
}

// IsResponse returns true iff the datagram looks like a FINS
// response (ICF response-bit set + minimum length). Lower-
// fidelity than ParseControllerDataRead; useful for the
// "responded but not the controller data" branch.
func IsResponse(buf []byte) bool {
	return len(buf) >= HeaderLen+2 && buf[0]&0x40 != 0
}
