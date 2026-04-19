package wire

import (
	"errors"
	"fmt"
	"io"
)

// PacketType enumerates the X.25 packet-level PTI values we recognise.
// Unknown values round-trip through the parser as PacketUnknown so
// fingerprinters can still record them.
type PacketType uint8

// X.25 PTI values relevant to fingerprinting a remote DCE/DTE. See
// ITU-T X.25 section 4. Data packets have PTI bit 0 == 0 and carry
// P(R)/M/P(S); those are collapsed here into a single PacketData.
const (
	PacketUnknown             PacketType = 0x00
	PacketCallRequest         PacketType = 0x0B // also: Incoming Call
	PacketCallAccepted        PacketType = 0x0F // also: Call Connected
	PacketClearRequest        PacketType = 0x13 // also: Clear Indication
	PacketClearConfirmation   PacketType = 0x17
	PacketReceiveReady        PacketType = 0x01 // RR
	PacketReceiveNotReady     PacketType = 0x05 // RNR
	PacketReject              PacketType = 0x09 // REJ
	PacketInterrupt           PacketType = 0x23
	PacketInterruptConfirm    PacketType = 0x27
	PacketResetRequest        PacketType = 0x1B // also: Reset Indication
	PacketResetConfirmation   PacketType = 0x1F
	PacketRestartRequest      PacketType = 0xFB // also: Restart Indication
	PacketRestartConfirmation PacketType = 0xFF
	PacketDiagnostic          PacketType = 0xF1
	PacketData                PacketType = 0x02 // umbrella: any PTI with bit 0 == 0
)

// packetTypeNames maps PacketType to its human-readable label. The
// indirection keeps String() under golangci-lint's gocyclo ceiling.
var packetTypeNames = map[PacketType]string{
	PacketCallRequest:         "CALL_REQUEST",
	PacketCallAccepted:        "CALL_ACCEPTED",
	PacketClearRequest:        "CLEAR_REQUEST",
	PacketClearConfirmation:   "CLEAR_CONFIRMATION",
	PacketReceiveReady:        "RECEIVE_READY",
	PacketReceiveNotReady:     "RECEIVE_NOT_READY",
	PacketReject:              "REJECT",
	PacketInterrupt:           "INTERRUPT",
	PacketInterruptConfirm:    "INTERRUPT_CONFIRMATION",
	PacketResetRequest:        "RESET_REQUEST",
	PacketResetConfirmation:   "RESET_CONFIRMATION",
	PacketRestartRequest:      "RESTART_REQUEST",
	PacketRestartConfirmation: "RESTART_CONFIRMATION",
	PacketDiagnostic:          "DIAGNOSTIC",
	PacketData:                "DATA",
}

// String returns a human-readable name.
func (p PacketType) String() string {
	if s, ok := packetTypeNames[p]; ok {
		return s
	}
	return "UNKNOWN"
}

// Packet is the decoded X.25 packet header.
type Packet struct {
	GFI     uint8      // General Format Identifier (top 4 bits of byte 0)
	LCN     uint16     // Logical Channel Number (12 bits spanning bytes 0-1)
	PTI     uint8      // raw PTI byte
	Type    PacketType // decoded type
	Payload []byte     // bytes after the PTI byte (caller owns)
}

// ErrShortPacket is returned when the X.25 payload is shorter than
// MinPayloadLen.
var ErrShortPacket = errors.New("xot/x25: packet shorter than 3 bytes")

// ParseX25 parses the full X.25 payload of one XOT frame.
func ParseX25(b []byte) (Packet, error) {
	if len(b) < MinPayloadLen {
		return Packet{}, fmt.Errorf("%w: have %d", ErrShortPacket, len(b))
	}
	if len(b) > MaxPayloadLen {
		return Packet{}, fmt.Errorf("%w: %d", ErrPayloadTooLong, len(b))
	}
	p := Packet{
		GFI:     b[0] >> 4,
		LCN:     uint16(b[0]&0x0f)<<8 | uint16(b[1]),
		PTI:     b[2],
		Payload: append([]byte(nil), b[3:]...),
	}
	p.Type = classifyPTI(p.PTI)
	return p, nil
}

// classifyPTI maps a PTI byte to a PacketType. Data packets (bit 0 == 0)
// collapse into PacketData so fingerprinters treat "any data-carrying
// packet" uniformly.
func classifyPTI(pti uint8) PacketType {
	if pti&0x01 == 0 {
		return PacketData
	}
	known := []PacketType{
		PacketCallRequest, PacketCallAccepted,
		PacketClearRequest, PacketClearConfirmation,
		PacketReceiveReady, PacketReceiveNotReady, PacketReject,
		PacketInterrupt, PacketInterruptConfirm,
		PacketResetRequest, PacketResetConfirmation,
		PacketRestartRequest, PacketRestartConfirmation,
		PacketDiagnostic,
	}
	for _, k := range known {
		if pti == uint8(k) {
			return k
		}
	}
	return PacketUnknown
}

// ClearCause extracts the cause code and diagnostic byte from a Clear
// Request / Clear Indication payload (ITU-T X.25 section 5.2.1).
// Returns (0, 0, ok=false) if the packet is not a clear or the
// payload is too short.
func ClearCause(p Packet) (cause, diag uint8, ok bool) {
	if p.Type != PacketClearRequest {
		return 0, 0, false
	}
	if len(p.Payload) < 2 {
		return 0, 0, false
	}
	return p.Payload[0], p.Payload[1], true
}

// MarshalCallRequest builds a minimal Call Request (PTI 0x0B) X.25
// payload with no called/calling addresses, facilities, or user data.
// LCN is embedded; GFI fixed at 0x1 (General Format Identifier for
// normal sequencing) per common practice.
func MarshalCallRequest(lcn uint16) []byte {
	return []byte{
		(0x1 << 4) | uint8((lcn>>8)&0x0f), // GFI | LCN hi
		uint8(lcn & 0xff),                 // LCN lo
		uint8(PacketCallRequest),
		0x00, // called address length (4 bits each called/calling = 0)
		0x00, // facilities length = 0
	}
}

// WriteXOTFrame writes one XOT frame (header + X.25 payload) to w.
func WriteXOTFrame(w io.Writer, x25 []byte) error {
	if len(x25) > MaxPayloadLen {
		return fmt.Errorf("%w: %d", ErrPayloadTooLong, len(x25))
	}
	if len(x25) < MinPayloadLen {
		return fmt.Errorf("%w: %d", ErrPayloadTooShort, len(x25))
	}
	// #nosec G115 -- len(x25) bounded above by MaxPayloadLen (4096)
	hdr := MarshalHeader(Header{Version: Version, Length: uint16(len(x25))})
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(x25); err != nil {
		return err
	}
	return nil
}

// ReadXOTFrame reads one XOT frame and returns the parsed packet.
func ReadXOTFrame(r io.Reader) (Packet, error) {
	h, err := ReadHeader(r)
	if err != nil {
		return Packet{}, err
	}
	buf := make([]byte, h.Length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return Packet{}, fmt.Errorf("xot: payload: %w", err)
	}
	return ParseX25(buf)
}
