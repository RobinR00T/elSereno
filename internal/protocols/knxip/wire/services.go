package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// KNXnet/IP service-type catalogue used by the offensive write
// gate (v1.55). The fingerprint plugin (v1.21 chunk 1) only needs
// the DESCRIPTION pair (0x0203/0x0204) so the offensive gating
// constants live here rather than inflating wire.go.
//
// Service types are 16-bit big-endian at offset [2:4] of every
// KNXnet/IP frame (KNX Standard 03.08.02 §2.2). Numbering is
// service-family << 8 | sub-code:
//
//	0x02xx  Core            (search, description, connect)
//	0x03xx  Device Mgmt     (device-config request/ack)
//	0x04xx  Tunnelling      (tunnelling request/ack)
//	0x05xx  Routing         (routing indication/lost/busy)
//	0x09xx  KNXnet/IP Secure (session bring-up, encrypted wrappers)
const (
	// --- Core (0x02xx) ---

	// ServiceTypeSearchRequest is the multicast SEARCH_REQUEST
	// (0x0201) — clients announce themselves to discover servers
	// on 224.0.23.12. Read-only; gate always-passes.
	ServiceTypeSearchRequest uint16 = 0x0201
	// ServiceTypeSearchResponse is the matching SEARCH_RESPONSE
	// (0x0202).
	ServiceTypeSearchResponse uint16 = 0x0202
	// ServiceTypeConnectRequest is CONNECT_REQUEST (0x0205) —
	// opens a tunnel / device-config / object-server session.
	// Gateable; allowing CONNECT without further filter lets the
	// client open a tunnel and then issue any TUNNELLING_REQUEST.
	ServiceTypeConnectRequest uint16 = 0x0205
	// ServiceTypeConnectResponse is the CONNECT_RESPONSE (0x0206).
	ServiceTypeConnectResponse uint16 = 0x0206
	// ServiceTypeConnectionStateRequest is the keep-alive ping
	// CONNECTIONSTATE_REQUEST (0x0207). Always-safe.
	ServiceTypeConnectionStateRequest uint16 = 0x0207
	// ServiceTypeConnectionStateResponse (0x0208).
	ServiceTypeConnectionStateResponse uint16 = 0x0208
	// ServiceTypeDisconnectRequest is DISCONNECT_REQUEST (0x0209).
	// Always-safe — operator may want to terminate a stuck
	// session.
	ServiceTypeDisconnectRequest uint16 = 0x0209
	// ServiceTypeDisconnectResponse (0x020A).
	ServiceTypeDisconnectResponse uint16 = 0x020A

	// --- Device Management (0x03xx) ---

	// ServiceTypeDeviceConfigurationRequest (0x0310) carries cEMI
	// M_PropRead / M_PropWrite / M_Reset frames that mutate
	// device-mgmt parameters (group-address table, LCN, IP
	// settings, factory reset). Gateable — fine-grained gating
	// at the M_PropWrite level is a future cycle (the cEMI parser
	// in this package extracts MsgCode but not yet object-id /
	// PID / element granularity for property writes).
	ServiceTypeDeviceConfigurationRequest uint16 = 0x0310
	// ServiceTypeDeviceConfigurationAck (0x0311).
	ServiceTypeDeviceConfigurationAck uint16 = 0x0311

	// --- Tunnelling (0x04xx) ---

	// ServiceTypeTunnellingRequest (0x0420) carries the actual KNX
	// bus telegram (cEMI L_Data.req / L_Data.ind frames). This is
	// THE write-gating service: APCI inside the cEMI controls
	// whether the request is a GroupValue_Read, GroupValue_Write,
	// IndividualAddress_Write, Memory_Write, etc. — the full
	// blast radius of a KNX bus.
	ServiceTypeTunnellingRequest uint16 = 0x0420
	// ServiceTypeTunnellingAck (0x0421). Always-safe.
	ServiceTypeTunnellingAck uint16 = 0x0421

	// --- Routing (0x05xx, multicast) ---

	// ServiceTypeRoutingIndication (0x0530) — multicast routing
	// of cEMI L_Data frames between IP-routers. Carries the same
	// bus blast radius as TUNNELLING_REQUEST. Gateable.
	ServiceTypeRoutingIndication uint16 = 0x0530
	// ServiceTypeRoutingLostMessage (0x0531). Read-only diag.
	ServiceTypeRoutingLostMessage uint16 = 0x0531
	// ServiceTypeRoutingBusy (0x0532). Read-only flow-control.
	ServiceTypeRoutingBusy uint16 = 0x0532
)

// --- cEMI Message Codes -----------------------------------------

// cEMI (common External Message Interface) message codes — the
// inner cEMI frame's first byte. Defined in KNX Standard 03.06.03
// §4.1.5.3.
//
//	0x11 L_Data.req         data link request from client
//	0x29 L_Data.ind         data link indication to client
//	0x2E L_Data.con         data link confirmation to client
//	0x10 L_Raw.req          raw request (rare)
//	0x2D L_Raw.ind          raw indication (rare)
//	0x2F L_Raw.con          raw confirmation (rare)
//	0xFC M_PropRead.req     property read request (DEVICE MGMT)
//	0xFB M_PropRead.con     property read confirmation
//	0xF6 M_PropWrite.req    property WRITE request — mutating
//	0xF5 M_PropWrite.con    property write confirmation
//	0xF1 M_Reset.req        device reset request — DESTRUCTIVE
const (
	CEMILDataReq  byte = 0x11
	CEMILDataInd  byte = 0x29
	CEMILDataCon  byte = 0x2E
	CEMIPropRead  byte = 0xFC
	CEMIPropWrite byte = 0xF6
	CEMIReset     byte = 0xF1
)

// --- APCI (Application Protocol Control Information) -----------

// APCI is the top 4 bits of the 10-bit APCI field inside a cEMI
// L_Data frame. Group-addressed services pack the operation here.
// Defined in KNX Standard 03.03.07 §3.2.
//
//	0x0   A_GroupValue_Read           read group object value
//	0x1   A_GroupValue_Response       value response (broadcast)
//	0x2   A_GroupValue_Write          WRITE group object value
//	0x3   (extension; rare)
//	Higher 4-bit APCIs encode A_IndividualAddress_Read,
//	A_ADC_Read, A_Memory_Read/Write, A_DeviceDescriptor_Read,
//	A_Restart, A_PropertyValue_Read/Write, etc. The 10-bit
//	encoding lives in bytes [tpci][apci] of the L_Data tail —
//	see ParseCEMILData for the extraction logic.
type APCI uint16

const (
	// APCIGroupValueRead is A_GroupValue_Read (0x000) — read a
	// group-object value. Read-only; always-safe.
	APCIGroupValueRead APCI = 0x000
	// APCIGroupValueResponse is A_GroupValue_Response (0x040) —
	// the value-broadcast response to a Read or unsolicited
	// status update. Read-only; always-safe.
	APCIGroupValueResponse APCI = 0x040
	// APCIGroupValueWrite is A_GroupValue_Write (0x080) — WRITES
	// a value to a group object. The flagship gating operation:
	// every "turn on light", "set thermostat", "open valve",
	// "unlock door" travels via this APCI.
	APCIGroupValueWrite APCI = 0x080
	// APCIIndividualAddressWrite is A_IndividualAddress_Write
	// (0x0C0) — re-assigns a device's individual address.
	// Devastating: bricks the bus addressing scheme.
	APCIIndividualAddressWrite APCI = 0x0C0
	// APCIMemoryWrite is A_Memory_Write (0x280) — writes raw
	// bytes to device memory. Used for parameter download +
	// firmware tampering.
	APCIMemoryWrite APCI = 0x280
	// APCIRestart is A_Restart (0x380) — soft-restart a device.
	APCIRestart APCI = 0x380
)

// CEMILData captures the parsed fields of a cEMI L_Data frame
// (MsgCode 0x11/0x29/0x2E). Sufficient for per-(group-address,
// APCI) write-gating decisions.
type CEMILData struct {
	// MsgCode is the cEMI Message Code (0x11/0x29/0x2E).
	MsgCode byte
	// SourceIA is the 16-bit Individual Address of the originator
	// (3.4.5 → 0x3445). Set by the IP-interface; clients usually
	// see 0x0000 since the gateway re-stamps.
	SourceIA uint16
	// DestAddr is the 16-bit destination — Group Address (e.g.,
	// 1/0/3 → 0x0803) when DestIsGroup, else Individual Address.
	DestAddr uint16
	// DestIsGroup is true when the Address Type bit is 1 (group).
	DestIsGroup bool
	// APCI is the 10-bit APCI (top 4 bits = service code, bottom
	// 6 bits = data for short-form GroupValue_Write etc.).
	APCI APCI
}

// Parse-error sentinels for cEMI / TUNNELLING extraction.
var (
	// ErrCEMITooShort means the cEMI body is shorter than the
	// 11-byte L_Data minimum.
	ErrCEMITooShort = errors.New("knxip: cEMI body shorter than L_Data minimum")
	// ErrCEMINotLData means the cEMI MsgCode is not one of the
	// L_Data variants (0x11/0x29/0x2E).
	ErrCEMINotLData = errors.New("knxip: cEMI MsgCode is not L_Data")
	// ErrTunnellingBodyTooShort means the TUNNELLING_REQUEST
	// body is shorter than the 4-byte connection-header.
	ErrTunnellingBodyTooShort = errors.New("knxip: TUNNELLING_REQUEST body shorter than connection-header")
	// ErrServiceTypeMissing means the buffer is shorter than the
	// 6-byte KNXnet/IP header.
	ErrServiceTypeMissing = errors.New("knxip: buffer shorter than KNXnet/IP header")
)

// ServiceType extracts the KNXnet/IP service-type from any frame.
// Returns ErrServiceTypeMissing on a short buffer.
func ServiceType(frame []byte) (uint16, error) {
	if len(frame) < int(HeaderLen) {
		return 0, ErrServiceTypeMissing
	}
	return binary.BigEndian.Uint16(frame[2:4]), nil
}

// ParseTunnellingCEMI extracts the cEMI L_Data fields from a
// TUNNELLING_REQUEST frame. Frame layout (KNX Standard 03.08.04
// §4.4.6):
//
//	0..5    KNXnet/IP header (service 0x0420)
//	6       structure-length of connection-header (0x04)
//	7       communication-channel ID
//	8       sequence counter
//	9       reserved (0x00)
//	10..    cEMI frame (variable)
//
// The cEMI frame layout for L_Data:
//
//	+0      MsgCode (0x11 = L_Data.req)
//	+1      additional-info length (0x00 typically)
//	+2..    additional info (skip)
//	+N      Control field 1 (frame format, repeat, broadcast,
//	        priority, ack-req, confirm)
//	+N+1    Control field 2 (address type bit 7, hop-count, ext
//	        format)
//	+N+2..3 Source Address
//	+N+4..5 Destination Address
//	+N+6    NPDU length (the data byte count following)
//	+N+7    TPCI byte (top 6 bits TPCI; bottom 2 bits APCI[9..8])
//	+N+8    APCI byte (top 2 bits APCI[7..6]; bottom 6 bits = data
//	        for short-form GroupValue_* services)
//	+N+9..  optional payload for long-form services
func ParseTunnellingCEMI(frame []byte) (CEMILData, error) {
	body, err := tunnellingBody(frame)
	if err != nil {
		return CEMILData{}, err
	}
	return ParseCEMILData(body)
}

// tunnellingBody returns the cEMI portion of a TUNNELLING_REQUEST
// frame (everything past the 6-byte KNXnet/IP header + 4-byte
// connection-header).
func tunnellingBody(frame []byte) ([]byte, error) {
	if len(frame) < int(HeaderLen)+4 {
		return nil, ErrTunnellingBodyTooShort
	}
	if frame[6] != 0x04 {
		// Connection-header structure-length must be 4.
		return nil, ErrTunnellingBodyTooShort
	}
	return frame[10:], nil
}

// ParseCEMILData extracts the L_Data fields from a raw cEMI body.
// Exposed for callers that already stripped the
// KNXnet/IP+connection-header (e.g. ROUTING_INDICATION which has
// no connection-header and starts the cEMI at offset 6 directly).
func ParseCEMILData(body []byte) (CEMILData, error) {
	if len(body) < 11 {
		return CEMILData{}, ErrCEMITooShort
	}
	msgCode := body[0]
	if msgCode != CEMILDataReq && msgCode != CEMILDataInd && msgCode != CEMILDataCon {
		return CEMILData{}, ErrCEMINotLData
	}
	addInfoLen := int(body[1])
	headerEnd := 2 + addInfoLen
	// Need: ctrl1 + ctrl2 + src(2) + dst(2) + npdulen(1) + tpci(1) + apci(1) = 9 bytes
	if len(body) < headerEnd+9 {
		return CEMILData{}, ErrCEMITooShort
	}
	ctrl2 := body[headerEnd+1]
	src := binary.BigEndian.Uint16(body[headerEnd+2 : headerEnd+4])
	dst := binary.BigEndian.Uint16(body[headerEnd+4 : headerEnd+6])
	tpci := body[headerEnd+7]
	apciByte := body[headerEnd+8]
	// 10-bit APCI: bottom 2 bits of TPCI = APCI[9..8]; top 4 bits
	// of apciByte = APCI[7..4]; bottom 6 bits of apciByte are
	// either the encoded data (short-form GroupValue services)
	// OR APCI[5..0] for long-form services. For gating purposes
	// the top-4-bit service code is what matters; we mask the
	// data tail off.
	apciTop := uint16(tpci&0x03) << 8
	apciMid := uint16(apciByte&0xF0) << 0
	apci := APCI(apciTop | apciMid)
	return CEMILData{
		MsgCode:     msgCode,
		SourceIA:    src,
		DestAddr:    dst,
		DestIsGroup: ctrl2&0x80 != 0,
		APCI:        apci,
	}, nil
}

// FormatGroupAddress renders a 16-bit Group Address in the
// canonical 3-level KNX form "main/middle/sub" (5/3/8 bits).
// 1/0/3 = 0x0803 → "1/0/3". Convenience helper for refusal logs.
func FormatGroupAddress(ga uint16) string {
	main := (ga >> 11) & 0x1F
	middle := (ga >> 8) & 0x07
	sub := ga & 0xFF
	return fmt.Sprintf("%d/%d/%d", main, middle, sub)
}
