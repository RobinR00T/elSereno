// Package wire implements the minimum subset of MELSEC SLMP
// (SeamLess Message Protocol) needed for read-only fingerprinting
// on TCP/5007. The on-wire layout is from Mitsubishi Electric
// SLMP Reference Manual SH(NA)-080956ENG. SLMP is the modern
// (2014+) replacement for MELSEC-A/3C/MC and ships across the
// Mitsubishi Electric iQ-R, iQ-F, Q-, L-, and FX-series PLCs and
// many compatible HMIs and motion controllers.
//
// This package implements ONLY the request builder + response
// parser for **READ CPU MODEL NAME** (command 0x0101, subcommand
// 0x0000) — the canonical read-only fingerprint. The response
// carries the 16-byte ASCII CPU model name + 2-byte CPU type code
// (e.g. "Q03UDVCPU      " + 0x4612). No memory device read or
// write services are implemented; v1.20 chunk 2 is read-only by
// design.
package wire

import (
	"encoding/binary"
	"errors"
	"strings"
)

// 3E binary frame layout (request):
//
//	Offset  Field                    Size  Description
//	0..1    Subheader                2     0x5000 LE = request
//	2       NetworkNo                1     0x00 = host network
//	3       PCNo                     1     0xFF = CPU
//	4..5    RequestDestModuleIONo    2     0x03FF LE = CPU
//	6       RequestDestModuleStnNo   1     0x00
//	7..8    RequestDataLength        2     LE: monitoring (2) + command (2) + subcommand (2) + payload
//	9..10   MonitoringTimer          2     0x0000 = no timeout
//	11..12  Command                  2     LE
//	13..14  Subcommand               2     LE
//	15+     payload                  …     command-specific
//
// 3E binary frame layout (response, success):
//
//	Offset  Field                    Size  Description
//	0..1    Subheader                2     0xD000 LE = response
//	2       NetworkNo                1
//	3       PCNo                     1
//	4..5    RequestDestModuleIONo    2
//	6       RequestDestModuleStnNo   1
//	7..8    ResponseDataLength       2     LE: end code (2) + payload
//	9..10   EndCode                  2     LE: 0x0000 = success
//	11+     payload                  …     command-specific
const (
	// HeaderLenRequest is the 9-byte 3E request header — through
	// the RequestDataLength field at offset 7..8 inclusive. The
	// monitoring timer + command + subcommand triple follows.
	HeaderLenRequest = 9
	// HeaderLenResponse is the 9-byte 3E response header —
	// through the ResponseDataLength field at offset 7..8
	// inclusive. The end code + payload follow.
	HeaderLenResponse = 9

	// SubheaderRequestLE is the little-endian 0x5000 (request).
	SubheaderRequestLE uint16 = 0x0050
	// SubheaderResponseLE is the little-endian 0xD000 (response).
	SubheaderResponseLE uint16 = 0x00D0

	// CommandReadCPUModelName + SubcommandZero is "Read CPU model
	// name" per SLMP Reference Manual §3.10 — returns the 16-byte
	// ASCII CPU model name + 2-byte CPU type code. Read-only.
	CommandReadCPUModelName uint16 = 0x0101
	// SubcommandZero is the standard sub-zero used by Read CPU
	// model name and a handful of other system commands.
	SubcommandZero uint16 = 0x0000

	// MaxResponseDataLength is the largest plausible response
	// data-length field. Anything bigger is either a corrupted
	// frame or a different protocol on port 5007. The largest
	// SLMP read returns ~960 words = 1920 bytes; 8192 is a
	// generous ceiling that still rejects garbage frames.
	MaxResponseDataLength = 8192
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface on
// the dashboard).
var (
	// ErrShortFrame means the datagram is shorter than the
	// 11-byte response header (or 13-byte minimum including the
	// end-code field).
	ErrShortFrame = errors.New("slmp: response shorter than minimum")
	// ErrNotResponse means the subheader is not 0xD000 (the
	// little-endian response marker).
	ErrNotResponse = errors.New("slmp: subheader is not the response marker (0xD000)")
	// ErrLengthMismatch means the response-data-length field
	// disagrees with the actual frame size or exceeds the
	// MaxResponseDataLength sanity ceiling.
	ErrLengthMismatch = errors.New("slmp: response-data-length disagrees with frame size")
	// ErrEndCodeNonZero means the CPU returned a non-zero end
	// code (refusal / unsupported command). The end code is at
	// bytes [9:11] of the response.
	ErrEndCodeNonZero = errors.New("slmp: end code non-zero (CPU refused)")
)

// CPUInfo captures the parsed READ CPU MODEL NAME response. v1.20
// chunk 2 surfaces the Model field as the fingerprint signal; the
// 2-byte CPUType code is exposed for operators who pull it from
// the REPL when the framework lands.
//
// Model is NUL-trimmed + space-trimmed ASCII (SLMP pads short
// models with 0x20 to 16 bytes).
type CPUInfo struct {
	// Model is the 16-byte ASCII CPU model name (e.g.
	// "Q03UDVCPU", "R04ENCPU", "L26CPU-BT").
	Model string
	// CPUType is the 2-byte little-endian CPU type code that
	// follows the Model field. Mitsubishi documents this value
	// per CPU; the plugin doesn't translate it (operators can
	// look it up against the Mitsubishi catalogue via the REPL
	// when the framework lands).
	CPUType uint16
}

// BuildReadCPUModelName crafts the 15-byte TCP frame that asks a
// MELSEC iQ-R / iQ-F / Q- / L- / FX-series CPU for its model name.
// Network=0, PC=0xFF, IO=0x03FF, station=0, monitoring timer=0
// (no timeout), command=0x0101, subcommand=0x0000.
//
// The frame is binary-stable (no caller-supplied service ID at
// this layer — SLMP doesn't have one for the basic 3E-frame
// command set; the higher-tier 4E / 1E frames carry a serial
// number that v1.20 chunk 2 doesn't use).
func BuildReadCPUModelName() []byte {
	// 11 (header) + 2 (monitoring) + 2 (command) + 2 (subcommand)
	// = 17 bytes. But the data-length field counts only the
	// monitoring + command + subcommand + payload — here 6 bytes.
	frame := make([]byte, 17)
	binary.LittleEndian.PutUint16(frame[0:2], SubheaderRequestLE)
	frame[2] = 0x00 // network
	frame[3] = 0xFF // PC
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF)
	frame[6] = 0x00 // station
	binary.LittleEndian.PutUint16(frame[7:9], 0x0006)
	binary.LittleEndian.PutUint16(frame[9:11], 0x0000) // monitoring
	binary.LittleEndian.PutUint16(frame[11:13], CommandReadCPUModelName)
	binary.LittleEndian.PutUint16(frame[13:15], SubcommandZero)
	return frame[:15]
}

// ParseReadCPUModelName validates a READ CPU MODEL NAME response
// and extracts the 16-byte Model + 2-byte CPUType. On any
// structural error the appropriate sentinel from this package is
// returned.
//
// Wire shape (success):
//
//	0..1    Subheader (0xD000 LE)
//	2..6    rest of 3E header
//	7..8    response data length (LE)  ← end code (2) + payload
//	9..10   end code (LE)              ← 0x0000 = success
//	11..26  model (16 bytes ASCII, padded with 0x20)
//	27..28  CPU type code (2 bytes LE)
//
// Total successful frame: 29 bytes (9 header + 2 end code + 16
// model + 2 CPU type code).
func ParseReadCPUModelName(buf []byte) (CPUInfo, error) {
	const minLen = HeaderLenResponse + 2 // header + end code
	if len(buf) < minLen {
		return CPUInfo{}, ErrShortFrame
	}
	if binary.LittleEndian.Uint16(buf[0:2]) != SubheaderResponseLE {
		return CPUInfo{}, ErrNotResponse
	}
	declaredLen := int(binary.LittleEndian.Uint16(buf[7:9]))
	if declaredLen > MaxResponseDataLength {
		return CPUInfo{}, ErrLengthMismatch
	}
	// ResponseDataLength counts everything from the end-code
	// onwards: end code (2) + payload. So the total frame size
	// is 9 (header) + declaredLen.
	if len(buf) != HeaderLenResponse+declaredLen {
		return CPUInfo{}, ErrLengthMismatch
	}
	endCode := binary.LittleEndian.Uint16(buf[9:11])
	if endCode != 0x0000 {
		return CPUInfo{}, ErrEndCodeNonZero
	}
	// Successful frame requires 16-byte model + 2-byte CPU type
	// = 18 bytes of payload. declaredLen must therefore be 20
	// (end code + payload).
	if declaredLen != 20 {
		return CPUInfo{}, ErrLengthMismatch
	}
	model := trimASCII(buf[11 : 11+16])
	cpuType := binary.LittleEndian.Uint16(buf[27:29])
	return CPUInfo{Model: model, CPUType: cpuType}, nil
}

// trimASCII strips trailing NULs and spaces and returns the
// remaining string. The cutset is "any of NUL/space" applied in a
// single pass, so a model padded with `... 0x20 0x00 0x20` trims
// cleanly from both directions of the trailing run (the order-
// dependent two-call form would leak embedded NULs).
// Embedded printable bytes mid-string are preserved.
func trimASCII(b []byte) string {
	return strings.TrimRight(string(b), "\x00 ")
}

// IsResponseFrame returns true iff the buffer's first two bytes
// match the SLMP response subheader (0xD000 LE) and the buffer
// is at least header-sized. Useful for the "responded but not the
// CPU model name" branch.
func IsResponseFrame(buf []byte) bool {
	if len(buf) < HeaderLenResponse {
		return false
	}
	return binary.LittleEndian.Uint16(buf[0:2]) == SubheaderResponseLE
}
