// Package wire implements the minimum subset of Beckhoff
// TwinCAT ADS / AMS over TCP needed for read-only
// fingerprinting on TCP/48898. ADS (Automation Device
// Specification) is the application-layer protocol that
// every TwinCAT runtime (TwinCAT 2 + TwinCAT 3 on Beckhoff
// IPCs, embedded PCs, EtherCAT-coupled CX devices, BC9XYZ
// bus terminals) speaks for engineering + runtime
// communication.
//
// AMS/TCP frame on the wire (TCP/48898):
//
//	0..1   Reserved (always 0x00 0x00)
//	2..5   Length (LE32, bytes that follow)
//	6..11  Target AMS Net ID (6 bytes; e.g. 192.168.0.1.1.1)
//	12..13 Target AMS Port (LE16; 350 = SystemService, 851
//	       = TC3 PLC1, 801 = TC2 PLC1, 10000 = R0)
//	14..19 Source AMS Net ID
//	20..21 Source AMS Port
//	22..23 Command ID (LE16)
//	24..25 State Flags (LE16; bit0 = response, bit2 = ADS cmd)
//	26..29 Data Length (LE32)
//	30..33 Error Code (LE32)
//	34..37 Invoke ID (LE32)
//	38..   Payload
//
// Total fixed header: 38 bytes. We send a "Read Device
// Info" command (id=0x0001) targeted at AMS port 10000
// (Router) which every TwinCAT runtime answers with the
// runtime's name + 4-byte version triple. A successful
// response has 8+24=32 bytes of payload: error(4) +
// version(4) + name(24, NUL-padded ASCII).
//
// The probe is read-only by design; no write/exec service
// is exposed.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// AMSPort* are the AMS service-port numbers the runtime
// listens on internally (multiplexed over the same TCP
// 48898 connection by the AMS Router).
const (
	// AMSPortRouter is AMS port 0x2710 (10000) — the
	// AMS Router service. Every TwinCAT runtime
	// listens here for service-discovery + global
	// device-info queries; we target it for the
	// fingerprint probe.
	AMSPortRouter uint16 = 10000
)

// ADS command IDs (subset; only the ones we use).
const (
	// CmdReadDeviceInfo returns runtime name + version.
	// Standardised by Beckhoff; works on TC2 + TC3.
	CmdReadDeviceInfo uint16 = 0x0001
)

// Frame size constants.
const (
	// AMSTCPHeaderLen is the 6-byte AMS/TCP framing
	// header (2 reserved + 4 length).
	AMSTCPHeaderLen = 6
	// AMSHeaderLen is the AMS routing header that
	// follows AMS/TCP.
	AMSHeaderLen = 32
	// FrameMinLen is the smallest frame we'll accept
	// (just the two headers, no payload).
	FrameMinLen = AMSTCPHeaderLen + AMSHeaderLen
	// MaxBodyLen caps the AMS/TCP Length field so a
	// hostile peer can't drive unbounded allocation.
	MaxBodyLen uint32 = 4096
)

// Sentinels surfaced to operators on classification
// failures.
var (
	// ErrShortFrame means the response is shorter than
	// the AMS/TCP + AMS routing headers require.
	ErrShortFrame = errors.New("twincat: short AMS frame")
	// ErrBadAMSTCP means the AMS/TCP framing bytes are
	// not the 0x00 0x00 reserved prefix.
	ErrBadAMSTCP = errors.New("twincat: bad AMS/TCP framing")
	// ErrLengthMismatch means the AMS/TCP Length field
	// claims more bytes than the frame contains, or
	// exceeds MaxBodyLen.
	ErrLengthMismatch = errors.New("twincat: AMS/TCP length mismatch")
	// ErrNotADSResponse means the State Flags don't
	// have the response bit set, OR the Command ID
	// doesn't match what we sent.
	ErrNotADSResponse = errors.New("twincat: not an ADS response")
)

// DeviceInfo is the parsed ReadDeviceInfo response payload.
type DeviceInfo struct {
	// MajorVersion / MinorVersion / VersionBuild are
	// the runtime's version triple (e.g. 3 / 1 / 4024
	// for TC3 build 4024).
	MajorVersion uint8
	MinorVersion uint8
	VersionBuild uint16
	// Name is the runtime's reported device name (16
	// bytes NUL-padded ASCII; "TCatPlcCtrl" / "TCatRTE"
	// / "TCatRouter" / "TC3 PLC1" etc.). Trimmed of
	// trailing NULs.
	Name string
}

// BuildReadDeviceInfo constructs the AMS/TCP + AMS frame
// for a Read Device Info request to the runtime's AMS
// Router (port 10000).
//
// targetNetID is the upstream's AMS Net ID. For initial
// fingerprint probes — when we don't yet know the device's
// real ID — we use the standard "I don't know yet, please
// reply anyway" convention of all-zero AMS Net ID; many
// TwinCAT runtimes answer regardless. Operators with the
// real ID can override via the plugin's NetID option.
func BuildReadDeviceInfo(targetNetID [6]byte) []byte {
	const adsRequest uint16 = 0x0004 // bit2 set = ADS command, bit0 clear = request
	frame := make([]byte, FrameMinLen)
	// AMS/TCP header
	frame[0] = 0x00
	frame[1] = 0x00
	binary.LittleEndian.PutUint32(frame[2:6], uint32(AMSHeaderLen))
	// AMS header
	copy(frame[6:12], targetNetID[:])
	binary.LittleEndian.PutUint16(frame[12:14], AMSPortRouter)
	// Source NetID + Port: zero — the runtime echoes them
	// back in the response, no routing needed for
	// fingerprint.
	copy(frame[14:20], make([]byte, 6))
	binary.LittleEndian.PutUint16(frame[20:22], 0)
	binary.LittleEndian.PutUint16(frame[22:24], CmdReadDeviceInfo)
	binary.LittleEndian.PutUint16(frame[24:26], adsRequest)
	binary.LittleEndian.PutUint32(frame[26:30], 0) // data length
	binary.LittleEndian.PutUint32(frame[30:34], 0) // error code (request)
	binary.LittleEndian.PutUint32(frame[34:38], 1) // invoke id (arbitrary nonce)
	return frame
}

// ParseDeviceInfo classifies a TCP/48898 reply as an AMS
// frame, validates the headers + flags, and extracts the
// DeviceInfo payload from a successful Read Device Info
// response.
//
// Returns the populated DeviceInfo on success. Any
// inconsistency (short frame, length mismatch, response
// bit not set) returns the appropriate sentinel.
func ParseDeviceInfo(buf []byte) (DeviceInfo, error) {
	if len(buf) < FrameMinLen {
		return DeviceInfo{}, fmt.Errorf("%w: %d bytes", ErrShortFrame, len(buf))
	}
	if buf[0] != 0x00 || buf[1] != 0x00 {
		return DeviceInfo{}, fmt.Errorf("%w: prefix=0x%02x%02x", ErrBadAMSTCP, buf[0], buf[1])
	}
	length := binary.LittleEndian.Uint32(buf[2:6])
	if length > MaxBodyLen {
		return DeviceInfo{}, fmt.Errorf("%w: length=%d > max", ErrLengthMismatch, length)
	}
	if int(length)+AMSTCPHeaderLen > len(buf) {
		return DeviceInfo{}, fmt.Errorf("%w: frame=%d, want %d", ErrLengthMismatch, len(buf), int(length)+AMSTCPHeaderLen)
	}
	cmd := binary.LittleEndian.Uint16(buf[22:24])
	flags := binary.LittleEndian.Uint16(buf[24:26])
	if cmd != CmdReadDeviceInfo || flags&0x0001 == 0 {
		return DeviceInfo{}, fmt.Errorf("%w: cmd=0x%04x flags=0x%04x", ErrNotADSResponse, cmd, flags)
	}
	dataLen := binary.LittleEndian.Uint32(buf[26:30])
	payloadStart := FrameMinLen
	if int(dataLen) < 8 {
		// Need at least error(4) + version(4) for a
		// minimum-valid response.
		return DeviceInfo{}, fmt.Errorf("%w: data=%d", ErrShortFrame, dataLen)
	}
	if payloadStart+int(dataLen) > len(buf) {
		return DeviceInfo{}, fmt.Errorf("%w: payload truncated", ErrLengthMismatch)
	}
	// Payload: error(4) + major(1) + minor(1) + build(2) + name(16)
	errCode := binary.LittleEndian.Uint32(buf[payloadStart : payloadStart+4])
	if errCode != 0 {
		return DeviceInfo{}, fmt.Errorf("%w: ADS error 0x%08x", ErrNotADSResponse, errCode)
	}
	major := buf[payloadStart+4]
	minor := buf[payloadStart+5]
	build := binary.LittleEndian.Uint16(buf[payloadStart+6 : payloadStart+8])
	name := ""
	if int(dataLen) >= 8+16 {
		raw := buf[payloadStart+8 : payloadStart+8+16]
		// NUL-trim.
		end := len(raw)
		for i, b := range raw {
			if b == 0 {
				end = i
				break
			}
		}
		name = string(raw[:end])
	}
	return DeviceInfo{
		MajorVersion: major,
		MinorVersion: minor,
		VersionBuild: build,
		Name:         name,
	}, nil
}
