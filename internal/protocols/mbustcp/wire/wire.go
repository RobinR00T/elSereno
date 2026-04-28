// Package wire implements the minimum subset of M-Bus (Meter
// Bus, EN 13757-3 + EN 13757-4) needed for read-only
// fingerprinting over TCP. M-Bus over TCP wraps the wired M-Bus
// frame format; common deployments use TCP/10001 (the most
// frequent shape on Internet-exposed gateways), with TCP/8888
// and TCP/2055 also seen.
//
// This package implements ONLY the request builder + response
// parser for **REQ_UD2** (request user data class 2) — the
// canonical "give me a measurement frame" query. The RSP_UD
// long-frame response carries the BCD ID + 3-letter manufacturer
// code + medium byte + version, which together fingerprint the
// meter. No SND_UD (write) services are implemented; v1.21 chunk 2
// is read-only by design.
package wire

import (
	"errors"
	"fmt"
)

// M-Bus frame layout (EN 13757-3 §5.2):
//
//	Long frame (variable data):
//	  Offset  Field        Size  Description
//	  0       Start        1     0x68
//	  1       L            1     length: bytes from C through CS exclusive (= 3 + UD len)
//	  2       L (repeat)   1     same as previous
//	  3       Start        1     0x68 again
//	  4       C            1     control field (direction + FCB/FCV)
//	  5       A            1     address (primary 0..250; 254 broadcast)
//	  6       CI           1     control information (e.g., 0x72 = variable data response)
//	  7..N    UD           …     user data
//	  N+1     CS           1     checksum: sum of [C..UD] mod 256
//	  N+2     Stop         1     0x16
//
//	Short frame (link layer):
//	  Offset  Field        Size  Description
//	  0       Start        1     0x10
//	  1       C            1
//	  2       A            1
//	  3       CS           1     C+A mod 256
//	  4       Stop         1     0x16
//
//	Single-byte ACK: 0xE5
const (
	StartLong     byte = 0x68
	StartShort    byte = 0x10
	StopByte      byte = 0x16
	ACKByte       byte = 0xE5
	CIVarDataResp byte = 0x72

	// ControlREQUD2 is the M-Bus control byte for REQ_UD2: master
	// to slave, FCB=1, FCV=1. Hex 0x5B is the canonical value
	// for the first request after a SND_NKE (link reset).
	ControlREQUD2 byte = 0x5B
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface on
// the dashboard).
var (
	// ErrShortFrame means the response is shorter than the
	// minimum long-frame length (12 bytes: header 4 + CAB CI 3 +
	// minimum UD 2 + CS Stop 2 + a placeholder 1).
	ErrShortFrame = errors.New("mbustcp: response shorter than minimum long-frame")
	// ErrBadStart means the Start byte is not 0x68 (long frame)
	// or 0x10 (short frame, unusual as a response).
	ErrBadStart = errors.New("mbustcp: response start byte is not 0x68 or 0x10")
	// ErrLengthMismatch means the L field disagrees with itself
	// (the two L bytes don't match) or with the actual frame
	// size.
	ErrLengthMismatch = errors.New("mbustcp: length field disagrees with frame size")
	// ErrBadStop means the frame doesn't end with 0x16.
	ErrBadStop = errors.New("mbustcp: response stop byte is not 0x16")
	// ErrChecksumMismatch means the computed checksum doesn't
	// match the byte at position N+1.
	ErrChecksumMismatch = errors.New("mbustcp: checksum mismatch")
	// ErrNotVarDataResponse means the CI byte is not 0x72
	// (variable data response) — we only fingerprint that shape.
	ErrNotVarDataResponse = errors.New("mbustcp: CI is not 0x72 (variable data response)")
)

// MeterInfo captures the parsed RSP_UD variable-data header. The
// 3-letter manufacturer ID + medium byte are the fingerprint
// signal; ID + version surface for REPL inspection when the
// framework lands.
type MeterInfo struct {
	// ID is the 4-byte BCD secondary address (e.g.,
	// 0x12345678).
	ID uint32
	// Manufacturer is the decoded 3-letter manufacturer code
	// (e.g., "ABB", "KAM" Kamstrup, "ELS" Elster, "SEN" Sensus).
	Manufacturer string
	// Version is the meter version byte.
	Version byte
	// Medium is the medium byte: 0x02=electricity, 0x03=gas,
	// 0x04=heat (volume measured at return), 0x06=warm water,
	// 0x07=water, 0x16=cold water, 0x17=heat-cost-allocator.
	Medium byte
}

// BuildREQUD2 crafts the 5-byte short frame requesting class-2
// user data from the meter at the given primary address (1..250).
// Address 0xFE (254) is broadcast for unsolicited probe; address
// 0xFD (253) is the "all" secondary-addressing query.
//
// Frame breakdown (for address 0xFE):
//
//	0x10 0x5B 0xFE 0x59 0x16
//	└─┬─┘ └─┬─┘ └──┬──┘ └─┬─┘ └─┬─┘
//	  │     │      │      │     stop
//	  │     │      │      checksum: 0x5B + 0xFE mod 256 = 0x59
//	  │     │      address (broadcast)
//	  │     control
//	  start
func BuildREQUD2(address byte) []byte {
	// Checksum: byte addition naturally wraps at 256.
	cs := ControlREQUD2 + address
	return []byte{StartShort, ControlREQUD2, address, cs, StopByte}
}

// ParseRSPUD validates a RSP_UD response and extracts the
// MeterInfo header. On any structural error the appropriate
// sentinel from this package is returned. Single-byte ACK
// (0xE5) responses return ErrShortFrame — the caller should
// classify those before calling Parse.
//
// Wire shape (success):
//
//	0..3    long-frame header (0x68 L L 0x68)
//	4       C (control, 0x08 = RSP_UD)
//	5       A (address echo)
//	6       CI (0x72 = variable data response)
//	7..10   ID (4 bytes BCD)
//	11..12  Manufacturer (2 bytes packed letters, LE)
//	13      Version
//	14      Medium
//	15      Access No
//	16      Status
//	17..18  Signature
//	19..    data records (variable)
//	N+1     CS
//	N+2     Stop (0x16)
func ParseRSPUD(buf []byte) (MeterInfo, error) {
	const minLen = 19 + 2 // through Status + 2-byte Signature, plus CS + Stop
	if len(buf) < minLen {
		return MeterInfo{}, ErrShortFrame
	}
	if buf[0] != StartLong || buf[3] != StartLong {
		return MeterInfo{}, ErrBadStart
	}
	if buf[1] != buf[2] {
		return MeterInfo{}, ErrLengthMismatch
	}
	declaredLen := int(buf[1]) // bytes from C..UD (inclusive of CI, exclusive of CS)
	// Total = 4 (header 0x68 L L 0x68) + declaredLen + 1 (CS) + 1 (Stop).
	expectedTotal := 6 + declaredLen
	if len(buf) != expectedTotal {
		return MeterInfo{}, ErrLengthMismatch
	}
	if buf[len(buf)-1] != StopByte {
		return MeterInfo{}, ErrBadStop
	}
	// Checksum: sum of [4..len-2] mod 256.
	var cs byte
	for i := 4; i < len(buf)-2; i++ {
		cs += buf[i]
	}
	if cs != buf[len(buf)-2] {
		return MeterInfo{}, ErrChecksumMismatch
	}
	if buf[6] != CIVarDataResp {
		return MeterInfo{}, ErrNotVarDataResponse
	}
	id := uint32(buf[7]) | uint32(buf[8])<<8 | uint32(buf[9])<<16 | uint32(buf[10])<<24
	manuID := uint16(buf[11]) | uint16(buf[12])<<8
	return MeterInfo{
		ID:           id,
		Manufacturer: decodeManufacturer(manuID),
		Version:      buf[13],
		Medium:       buf[14],
	}, nil
}

// decodeManufacturer unpacks the 16-bit M-Bus manufacturer code
// into a 3-letter ASCII string per EN 13757-3 §5.6:
// M = (c1 - 'A' + 1) * 32^2 + (c2 - 'A' + 1) * 32 + (c3 - 'A' + 1)
// where 'A' encodes as 1, ..., 'Z' as 26.
//
// Common values: 0x0442 = "ABB" (ABB), 0x2C2D = "KAM" (Kamstrup),
// 0x1593 = "ELS" (Elster), 0x4D2D = "SEN" (Sensus).
func decodeManufacturer(m uint16) string {
	c1 := byte(m>>10&0x1F) + 'A' - 1
	c2 := byte(m>>5&0x1F) + 'A' - 1
	c3 := byte(m&0x1F) + 'A' - 1
	if !isASCIILetter(c1) || !isASCIILetter(c2) || !isASCIILetter(c3) {
		return fmt.Sprintf("0x%04x", m)
	}
	return string([]byte{c1, c2, c3})
}

func isASCIILetter(b byte) bool {
	return b >= 'A' && b <= 'Z'
}

// IsRSPUD returns true iff the buffer looks like a long-frame
// RSP_UD: 0x68 start, two matching L bytes, 0x68 again, valid
// stop byte, CI=0x72 at offset 6.
func IsRSPUD(buf []byte) bool {
	if len(buf) < 8 {
		return false
	}
	if buf[0] != StartLong || buf[3] != StartLong {
		return false
	}
	if buf[1] != buf[2] {
		return false
	}
	if buf[len(buf)-1] != StopByte {
		return false
	}
	return buf[6] == CIVarDataResp
}

// IsACK returns true iff the buffer is the single-byte M-Bus
// ACK (0xE5).
func IsACK(buf []byte) bool {
	return len(buf) == 1 && buf[0] == ACKByte
}
