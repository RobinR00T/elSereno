// Package wire implements the minimum subset of KNXnet/IP needed
// for read-only fingerprinting on UDP/3671. The on-wire layout is
// from the KNX Standard 03.08.02 (Core) — KNXnet/IP services
// CONNECT, DESCRIPTION, SEARCH, DEVICE MANAGEMENT.
//
// This package implements ONLY the request builder + response
// parser for **DESCRIPTION_REQUEST** (service type 0x0204) — the
// canonical "describe yourself" query. The DESCRIPTION_RESPONSE
// (0x0205) carries a Device Hardware DIB (device info block) +
// Supported Service Families DIB; the device hardware DIB has
// the 30-byte ASCII friendly name + KNX Address + KNX serial
// number + KNX MAC address + multicast address + project
// installation ID. The friendly name is the fingerprint signal.
//
// No tunnelling / device-management / routing services are
// implemented; v1.21 chunk 1 is read-only by design.
package wire

import (
	"encoding/binary"
	"errors"
	"strings"
)

// KNXnet/IP frame layout (KNX Standard 03.08.02 §2.2):
//
//	Offset  Field             Size  Description
//	0       HeaderLen         1     Always 0x06
//	1       ProtocolVersion   1     0x10 = KNXnet/IP 1.0
//	2..3    ServiceType       2     BE
//	4..5    TotalLength       2     BE: total frame length
//	6+      body              …     service-specific
const (
	// HeaderLen is the canonical 6-byte KNXnet/IP header.
	HeaderLen byte = 0x06
	// ProtocolVersion10 is KNXnet/IP 1.0.
	ProtocolVersion10 byte = 0x10

	// ServiceTypeDescriptionRequest is the "describe yourself"
	// request (0x0204).
	ServiceTypeDescriptionRequest uint16 = 0x0204
	// ServiceTypeDescriptionResponse is the matching response
	// (0x0205).
	ServiceTypeDescriptionResponse uint16 = 0x0205

	// HPAILen is the canonical Host Protocol Address Information
	// length: 1 byte struct-len + 1 byte protocol code + 4 byte
	// IPv4 address + 2 byte port = 8 bytes.
	HPAILen byte = 0x08
	// HPAIProtocolUDP is the IPv4 UDP host-protocol code (0x01).
	HPAIProtocolUDP byte = 0x01

	// DIBTypeDeviceInfo is the Device Hardware DIB type code.
	DIBTypeDeviceInfo byte = 0x01

	// DescriptionRequestLen is the total request length: 6
	// header + 8 control HPAI = 14 bytes.
	DescriptionRequestLen = 14

	// DescriptionResponseMinLen is the smallest sensible
	// response: 6 header + 54 device-info DIB = 60 bytes.
	DescriptionResponseMinLen = 60
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface on
// the dashboard).
var (
	// ErrShortFrame means the response is shorter than the 6-
	// byte KNXnet/IP header (or the 60-byte description-response
	// minimum).
	ErrShortFrame = errors.New("knxip: response shorter than minimum")
	// ErrBadHeader means the first byte is not 0x06 (header
	// length) or the second is not 0x10 (protocol version 1.0).
	ErrBadHeader = errors.New("knxip: header bytes are not 0x06 0x10")
	// ErrNotResponse means the service-type field is not the
	// DESCRIPTION_RESPONSE marker (0x0205).
	ErrNotResponse = errors.New("knxip: service type is not 0x0205 (DESCRIPTION_RESPONSE)")
	// ErrLengthMismatch means the TotalLength field disagrees
	// with the actual frame size.
	ErrLengthMismatch = errors.New("knxip: total-length field disagrees with frame size")
	// ErrMissingDeviceInfoDIB means the response did not contain
	// a Device Hardware DIB (type 0x01) at the canonical offset.
	ErrMissingDeviceInfoDIB = errors.New("knxip: device-info DIB (0x01) not at offset 6")
)

// DeviceInfo captures the parsed Device Hardware DIB from a
// DESCRIPTION_RESPONSE. The friendly name is the fingerprint
// signal; the medium / device status / KNX address surface for
// REPL inspection when the framework lands.
//
// FriendlyName is NUL-trimmed + space-trimmed ASCII (KNX pads
// short names with 0x00 to 30 bytes).
type DeviceInfo struct {
	// KNXMedium is the medium type byte: 0x01 reserved, 0x02 TP1,
	// 0x04 PL110, 0x10 RF, 0x20 IP.
	KNXMedium byte
	// DeviceStatus is the program-mode flag (bit 0).
	DeviceStatus byte
	// KNXIndividualAddress is the 16-bit KNX Individual Address
	// (e.g., 1.1.1 encoded as 0x1101).
	KNXIndividualAddress uint16
	// FriendlyName is the up-to-30-byte ASCII device friendly
	// name (e.g., "MDT IP Interface", "Gira Standard").
	FriendlyName string
}

// BuildDescriptionRequest crafts the 14-byte UDP datagram that
// asks a KNXnet/IP server to describe itself. The control HPAI
// uses 0.0.0.0:0 ("anonymous endpoint") which is the canonical
// shape for unsolicited probes — the server responds to the
// source address of the inbound datagram.
//
// Frame breakdown:
//
//	06 10 02 04 00 0E              ← header: len, version, svc, total
//	08 01 00 00 00 00 00 00         ← control HPAI: 0.0.0.0:0
func BuildDescriptionRequest() []byte {
	frame := make([]byte, DescriptionRequestLen)
	frame[0] = HeaderLen
	frame[1] = ProtocolVersion10
	binary.BigEndian.PutUint16(frame[2:4], ServiceTypeDescriptionRequest)
	binary.BigEndian.PutUint16(frame[4:6], DescriptionRequestLen)
	frame[6] = HPAILen
	frame[7] = HPAIProtocolUDP
	// frame[8:12] = 0.0.0.0 (already zero)
	// frame[12:14] = 0 (port; already zero)
	return frame
}

// ParseDescriptionResponse validates a DESCRIPTION_RESPONSE and
// extracts the Device Hardware DIB. On any structural error the
// appropriate sentinel from this package is returned.
//
// Wire shape (success):
//
//	0..5    KNXnet/IP header (svc 0x0205)
//	6       Device-info DIB length (0x36 = 54 bytes)
//	7       DIB type (0x01 = Device Hardware)
//	8       KNX Medium
//	9       Device Status
//	10..11  KNX Individual Address
//	12..13  Project Installation ID
//	14..19  KNX Serial Number
//	20..23  Multicast Address
//	24..29  KNX MAC Address
//	30..59  Friendly name (30-byte ASCII, padded with 0x00)
func ParseDescriptionResponse(buf []byte) (DeviceInfo, error) {
	if len(buf) < DescriptionResponseMinLen {
		return DeviceInfo{}, ErrShortFrame
	}
	if buf[0] != HeaderLen || buf[1] != ProtocolVersion10 {
		return DeviceInfo{}, ErrBadHeader
	}
	if binary.BigEndian.Uint16(buf[2:4]) != ServiceTypeDescriptionResponse {
		return DeviceInfo{}, ErrNotResponse
	}
	totalLen := int(binary.BigEndian.Uint16(buf[4:6]))
	if totalLen < DescriptionResponseMinLen || totalLen > len(buf) {
		return DeviceInfo{}, ErrLengthMismatch
	}
	if buf[7] != DIBTypeDeviceInfo {
		return DeviceInfo{}, ErrMissingDeviceInfoDIB
	}
	if buf[6] < 0x36 {
		return DeviceInfo{}, ErrShortFrame
	}
	// Bytes [30..60) are the friendly name (30 bytes ASCII).
	name := trimASCII(buf[30:60])
	return DeviceInfo{
		KNXMedium:            buf[8],
		DeviceStatus:         buf[9],
		KNXIndividualAddress: binary.BigEndian.Uint16(buf[10:12]),
		FriendlyName:         name,
	}, nil
}

// trimASCII strips trailing NULs and spaces and returns the
// remaining string. The cutset is "any of NUL/space" applied in a
// single pass so order-dependent two-call forms can't leak
// embedded NULs.
func trimASCII(b []byte) string {
	return strings.TrimRight(string(b), "\x00 ")
}

// IsDescriptionResponse returns true iff the buffer looks like a
// KNXnet/IP DESCRIPTION_RESPONSE: 60-byte minimum, header bytes
// 0x06 0x10, service type 0x0205. Useful for the "responded but
// not the description shape" branch.
func IsDescriptionResponse(buf []byte) bool {
	if len(buf) < DescriptionResponseMinLen {
		return false
	}
	if buf[0] != HeaderLen || buf[1] != ProtocolVersion10 {
		return false
	}
	return binary.BigEndian.Uint16(buf[2:4]) == ServiceTypeDescriptionResponse
}
