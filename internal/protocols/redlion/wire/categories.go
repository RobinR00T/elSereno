package wire

// Red Lion Crimson v3 (CR3) packet-type classification for the proxy
// write-gating matrix (ADR-040).
//
// SOURCE: the CR3 frame layout and the Type opcodes below are taken
// from the public internetofallthethings/cr3-wireshark dissector
// (mirrored in weaponize/redlion), the only open description of the
// Crimson v3 link protocol on TCP/789. That dissector's own README
// calls it "a minimal dissector ... a starting point": it establishes
// the wire framing and enumerates the Type opcodes, but it does NOT
// authoritatively label every opcode read-vs-write. We therefore
// classify conservatively and fail closed — only opcodes whose payload
// carries an explicit READ-request structure are auto-passed; the
// opcodes whose payload is clearly mutating data are the known writes;
// every other opcode is CategoryUnknown and refused unless the
// operator explicitly allowlists it after establishing its semantics
// in their own environment.
//
// CR3 frame (all fields big-endian):
//   off 0  uint16 length   (total wire bytes = length + 2)
//   off 2  uint16 reg      (register number)
//   off 4  uint16 type     (the opcode / packet type)
//   off 6+ type-specific payload

import (
	"encoding/binary"
	"errors"
	"io"
)

// PacketType is the CR3 Type opcode at frame offset 4.
type PacketType uint16

// Category groups CR3 packet types for the proxy allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback; the proxy refuses it unless the
	// operator allowlists the type.
	CategoryUnknown Category = iota
	// CategoryRead covers opcodes whose payload is an explicit read
	// request (no mutation of controller state, config, or firmware).
	CategoryRead
	// CategoryWrite covers opcodes that push data, values, or config/
	// firmware chunks to the device.
	CategoryWrite
)

// Named packet types (from the dissector's type-specific handling).
const (
	// Read-request opcodes.
	TypeMemRead PacketType = 0x1b00 // zero + readoffset + readlength
	TypePoll    PacketType = 0x1700 // reads a value (dissector: "seems to always read 0x7530")

	// Mutating opcodes.
	TypeRegPush     PacketType = 0x0300 // pushes data/string to a register
	TypeValueWrite  PacketType = 0x1300 // sequence + subtype + 32-bit value
	TypeValueWrite2 PacketType = 0x1400
	TypeChunk       PacketType = 0x1500 // chunkstart + chunklength + chunkdata (config/firmware upload)
	TypeChunk2      PacketType = 0x1200
	TypeChunk3      PacketType = 0x1202
)

// readTypes is the deliberately-narrow auto-pass set: only opcodes the
// dissector shows to carry an explicit read-request structure. SAFETY
// INVARIANT: no opcode here may push data, values, or config to the
// device. Handshake / no-payload opcodes are intentionally NOT here —
// a no-payload command can be a mutating action (commit, reboot), and
// the public dissector does not establish otherwise.
var readTypes = map[PacketType]struct{}{
	TypeMemRead: {}, // 0x1b00: read readlength bytes at readoffset
	TypePoll:    {}, // 0x1700: value poll / keepalive read
}

// writeTypes are the well-known mutating opcodes (for intelligible
// audit). Membership here is not required for refusal — anything not
// in readTypes is refused unless allowlisted — but naming them keeps
// the audit trail legible.
var writeTypes = map[PacketType]struct{}{
	TypeRegPush:     {}, // 0x0300: register data/string push
	TypeValueWrite:  {}, // 0x1300: value write
	TypeValueWrite2: {}, // 0x1400: value write
	TypeChunk:       {}, // 0x1500: config/firmware chunk upload
	TypeChunk2:      {}, // 0x1200: chunk upload
	TypeChunk3:      {}, // 0x1202: chunk upload
}

// ClassifyType returns the Category for a CR3 packet type. Opcodes in
// neither table return CategoryUnknown, which the proxy refuses unless
// allowlisted. (The package already has a banner-level Classify(buf)
// for fingerprinting; this is the write-gate opcode classifier.)
func ClassifyType(t PacketType) Category {
	if _, ok := readTypes[t]; ok {
		return CategoryRead
	}
	if _, ok := writeTypes[t]; ok {
		return CategoryWrite
	}
	return CategoryUnknown
}

// ---- CR3 frame reading (write-gate framing) ------------------------

// ErrShortCR3Frame means a frame's length field is too small to carry
// the reg + type header (a well-formed CR3 frame has length >= 4).
var ErrShortCR3Frame = errors.New("redlion: CR3 frame length < 4 (no reg+type)")

// cr3TypeOffset is the absolute offset of the Type opcode in a frame.
const cr3TypeOffset = 4

// minLengthField is the smallest CR3 length field that still carries
// reg(2) + type(2).
const minLengthField = 4

// ReadFrame reads one length-prefixed CR3 frame from r and returns the
// complete frame bytes (the 2-byte length field followed by its
// `length` body bytes). The CR3 length is big-endian and counts only
// the body, so the returned slice is len(2)+length bytes. A length
// below the reg+type minimum returns ErrShortCR3Frame (fail-closed).
func ReadFrame(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	bodyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if bodyLen < minLengthField {
		return nil, ErrShortCR3Frame
	}
	frame := make([]byte, 2+bodyLen)
	frame[0], frame[1] = lenBuf[0], lenBuf[1]
	if _, err := io.ReadFull(r, frame[2:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// ExtractType returns the CR3 Type opcode from a complete frame. ok is
// false when the frame is too short to hold the opcode.
func ExtractType(frame []byte) (PacketType, bool) {
	if len(frame) < cr3TypeOffset+2 {
		return 0, false
	}
	return PacketType(binary.BigEndian.Uint16(frame[cr3TypeOffset : cr3TypeOffset+2])), true
}
