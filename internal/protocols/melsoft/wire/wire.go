// Package wire implements the minimum subset of the Mitsubishi
// Electric MELSOFT protocol needed for read-only fingerprinting on
// TCP/5007. MELSOFT is the engineering protocol that GX Works2 / GX
// Works3 (and the MELSOFT transparent gateway) speak to a MELSEC CPU over
// Ethernet; it is distinct from SLMP (MC 3E, subheader 0x50/0xD0 on a
// user-configured port). TCP/5007 is the QnUCPU built-in Ethernet port's
// system "MELSOFT communication port (TCP/IP)" (SH(NA)-080811ENG,
// Appendix 2; E71 modules use TCP/5002), and its frames use a 0x57
// (request) / 0xD7 (response) marker.
//
// This package implements ONLY the fixed "get CPU info" request and
// the response parser that extracts the 16-byte ASCII CPU model name.
// It is the canonical read-only fingerprint; no memory-device read or
// write services are implemented.
//
// Wire layout is reverse-engineered from a real capture
// (hi-KK/ICS-Protocol-identify "Mitsubishi Q系列PLC CPU型号识别",
// TCP/5007) and the DigitalBond / plcscan melsecq-discover.nse shipped
// alongside it, which agree byte for byte: the request is the fixed
// 41-byte getcpuinfopack, and the response is validated by a leading
// 0xD7 marker with the CPU model name at offset 41.
package wire

import (
	"bytes"
	"errors"
	"strings"
)

const (
	// RequestMarker is byte 0 of a MELSOFT request (0x57).
	RequestMarker byte = 0x57
	// ResponseMarker is byte 0 of a MELSOFT response (0x57 + 0x80).
	ResponseMarker byte = 0xD7

	// ModelOffset is the byte offset of the 16-byte ASCII CPU model
	// name in a get-CPU-info response (melsecq-discover.nse reads it
	// at 1-based offset 42, i.e. 0-based 41).
	ModelOffset = 41
	// ModelLen is the CPU model name field width (padded with 0x20).
	ModelLen = 16
	// MinResponseLen is the smallest response that can carry a model.
	MinResponseLen = ModelOffset + ModelLen
)

// GetCPUInfoRequest is the fixed 41-byte MELSOFT "get CPU info"
// request, verbatim from melsecq-discover.nse (getcpuinfopack) and the
// real capture. The embedded 0x0101 is the read-CPU-model command,
// the same command id SLMP uses for the equivalent read.
var GetCPUInfoRequest = []byte{
	0x57, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x07,
	0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0xfe,
	0x03, 0x00, 0x00, 0x14, 0x00, 0x1c, 0x08, 0x0a,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x01,
}

// Sentinel errors so callers can distinguish parser-failure classes.
var (
	// ErrShortFrame means the response is shorter than the 2-byte
	// response marker.
	ErrShortFrame = errors.New("melsoft: response shorter than the 2-byte response marker")
	// ErrNotResponse means byte 0 is not the 0xD7 MELSOFT response
	// marker (so this is not a MELSOFT reply).
	ErrNotResponse = errors.New("melsoft: byte 0 is not the response marker (0xD7)")
)

// CPUInfo captures the parsed get-CPU-info response. Model is the ASCII
// CPU model name read up to the first NUL with the 0x20 padding trimmed
// (e.g. "Q03UDECPU"); it is
// empty when the response is a valid MELSOFT frame but too short to
// carry a model or the model field is blank.
type CPUInfo struct {
	Model string
}

// BuildGetCPUInfo returns a copy of the fixed MELSOFT get-CPU-info
// request. A real MELSOFT endpoint on TCP/5007 replies with a frame
// whose first byte is 0xD7 (see ParseCPUInfo).
func BuildGetCPUInfo() []byte {
	out := make([]byte, len(GetCPUInfoRequest))
	copy(out, GetCPUInfoRequest)
	return out
}

// IsResponseFrame returns true iff the buffer begins with the 2-byte
// MELSOFT response marker (0xD7 0x00).
func IsResponseFrame(buf []byte) bool {
	return len(buf) >= 2 && buf[0] == ResponseMarker && buf[1] == 0x00
}

// ParseCPUInfo validates a MELSOFT get-CPU-info response and extracts
// the CPU model name when present. The positive identification is the
// 0xD7 response marker; the model is a best-effort extraction at the
// reference offset, so a valid-marker frame that is too short or whose
// model field is blank returns a CPUInfo with an empty Model and no
// error (the caller still has a positive MELSOFT identification).
func ParseCPUInfo(buf []byte) (CPUInfo, error) {
	if len(buf) < 2 {
		return CPUInfo{}, ErrShortFrame
	}
	if buf[0] != ResponseMarker || buf[1] != 0x00 {
		return CPUInfo{}, ErrNotResponse
	}
	if len(buf) < MinResponseLen {
		return CPUInfo{}, nil // valid marker, no room for a model
	}
	return CPUInfo{Model: modelField(buf[ModelOffset : ModelOffset+ModelLen])}, nil
}

// modelField reads the 16-byte model name the way the reference
// melsecq-discover.nse does (a NUL-terminated string, at most 16 bytes):
// it stops at the first NUL, then drops the trailing 0x20 padding. Stopping
// at the NUL keeps bytes after a terminator out of the model (a plain
// trailing-trim would keep "MODEL\x00junk" as "MODEL\x00junk").
func modelField(b []byte) string {
	if i := bytes.IndexByte(b, 0x00); i >= 0 {
		b = b[:i]
	}
	return strings.TrimRight(string(b), " ")
}
