package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Port is the TriStation UDP port.
const Port = 1502

// TCM opcodes (first byte of every datagram).
const (
	OpConnectRequest    byte = 1
	OpConnectReply      byte = 2
	OpDisconnectReply   byte = 3
	OpDisconnectRequest byte = 4
	OpCommand           byte = 5
	OpPing              byte = 6
	OpConnLimitReached  byte = 7
	OpNotConnected      byte = 8
	OpMPsAreDead        byte = 9
	OpAccessDenied      byte = 10
	OpConnectionFailed  byte = 11
)

// TriStation commands used or reported by elSereno.
const (
	CmdStartDownloadAll    byte = 0
	CmdStartDownloadChange byte = 1
	CmdGetCPStatus         byte = 19
	CmdRunProgram          byte = 20
	CmdHaltProgram         byte = 21
	CmdAllocateProgram     byte = 55
	CmdAllocateFunction    byte = 56
	CmdUploadProgram       byte = 65
	CmdUploadFunction      byte = 66
	CmdCommandRejected     byte = 100
	CmdCPStatusResponse    byte = 108
)

const (
	tcmHeaderLen = 4
	tsHeaderLen  = 10
	crcLen       = 2
)

// Errors returned by Parse.
var (
	ErrShort     = errors.New("tristation: frame too short")
	ErrLength    = errors.New("tristation: length field disagrees with the frame")
	ErrBadCRC    = errors.New("tristation: CRC-16 mismatch")
	ErrNotStatus = errors.New("tristation: not a Get CP status response")
)

// CRC16 is CRC-16/ARC (reflected polynomial 0xA001, initial value 0, no
// final XOR), the TCM frame check.
func CRC16(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c ^= uint16(x)
		for i := 0; i < 8; i++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xA001
			} else {
				c >>= 1
			}
		}
	}
	return c
}

// appendCRC appends the little-endian CRC of b.
func appendCRC(b []byte) []byte {
	return binary.LittleEndian.AppendUint16(b, CRC16(b))
}

// BuildConnect returns the CONNECT REQUEST datagram (channel 0).
func BuildConnect() []byte {
	return appendCRC([]byte{OpConnectRequest, 0, 0, 0})
}

// BuildDisconnect returns the DISCONN REQUEST datagram (channel 0).
func BuildDisconnect() []byte {
	return appendCRC([]byte{OpDisconnectRequest, 0, 0, 0})
}

// BuildCommand returns a COMMAND datagram on channel 0 from the
// workstation (path 0, connection id 0) carrying cmd and data.
func BuildCommand(cmd, seq byte, data []byte) ([]byte, error) {
	tsLen := tsHeaderLen + len(data)
	if tsLen > 0xFFFF {
		return nil, fmt.Errorf("tristation: command data too long (%d bytes)", len(data))
	}
	n := uint16(tsLen) // #nosec G115 -- bounded by the check above
	b := make([]byte, 0, tcmHeaderLen+tsLen+crcLen)
	b = append(b, OpCommand, 0)
	b = binary.LittleEndian.AppendUint16(b, n)
	hdr := []byte{0, 0, cmd, seq, 0, 0}
	sum := uint32(n) + byteSum(hdr) + byteSum([]byte{byte(n & 0xff), byte(n >> 8 & 0xff)}) + byteSum(data)
	b = append(b, hdr...)
	b = binary.LittleEndian.AppendUint16(b, uint16(sum)) // #nosec G115 -- the protocol keeps the low 16 bits
	b = binary.LittleEndian.AppendUint16(b, n)
	b = append(b, data...)
	return appendCRC(b), nil
}

// BuildGetCPStatus returns the Get CP status command (no data). It is a
// read: the controller answers with its key switch, run state and
// project, and changes nothing.
func BuildGetCPStatus(seq byte) []byte {
	b, _ := BuildCommand(CmdGetCPStatus, seq, nil) // cannot fail: no data
	return b
}

func byteSum(b []byte) uint32 {
	var s uint32
	for _, x := range b {
		s += uint32(x)
	}
	return s
}

// TSHeader is the TriStation header of a COMMAND frame.
type TSHeader struct {
	Path       byte   `json:"path"` // 0 workstation->controller, 1 controller->workstation
	CID        byte   `json:"cid"`
	Command    byte   `json:"command"`
	Seq        byte   `json:"seq"`
	Checksum   uint16 `json:"checksum"`
	Length     uint16 `json:"length"`
	ChecksumOK bool   `json:"checksum_ok"`
}

// Frame is a decoded TCM datagram.
type Frame struct {
	Opcode  byte      `json:"opcode"`
	Channel byte      `json:"channel"`
	TS      *TSHeader `json:"ts,omitempty"`
	// Data is the TriStation command data (after the 10-byte header).
	Data []byte `json:"-"`
	raw  []byte
}

// Parse decodes one datagram. It checks the length field and the CRC
// before returning anything; trailing bytes after the CRC (Ethernet
// padding in a capture) are ignored.
func Parse(b []byte) (Frame, error) {
	if len(b) < tcmHeaderLen+crcLen {
		return Frame{}, ErrShort
	}
	n := int(binary.LittleEndian.Uint16(b[2:4]))
	end := tcmHeaderLen + n
	if len(b) < end+crcLen {
		return Frame{}, ErrLength
	}
	if CRC16(b[:end]) != binary.LittleEndian.Uint16(b[end:end+crcLen]) {
		return Frame{}, ErrBadCRC
	}
	f := Frame{Opcode: b[0], Channel: b[1], raw: b[:end]}
	if n == 0 {
		return f, nil
	}
	if n < tsHeaderLen {
		return Frame{}, ErrLength
	}
	ts := b[tcmHeaderLen:end]
	h := &TSHeader{
		Path: ts[0], CID: ts[1], Command: ts[2], Seq: ts[3],
		Checksum: binary.LittleEndian.Uint16(ts[6:8]),
		Length:   binary.LittleEndian.Uint16(ts[8:10]),
	}
	if int(h.Length) != n {
		return Frame{}, ErrLength
	}
	sum := uint32(h.Length) + byteSum(ts[0:6]) + byteSum(ts[8:])
	h.ChecksumOK = uint16(sum) == h.Checksum // #nosec G115 -- the protocol keeps the low 16 bits
	f.TS = h
	f.Data = ts[tsHeaderLen:]
	return f, nil
}

// OpcodeName names a TCM opcode.
func OpcodeName(op byte) string {
	switch op {
	case OpConnectRequest:
		return "CONNECT REQUEST"
	case OpConnectReply:
		return "CONNECT REPLY"
	case OpDisconnectReply:
		return "DISCONN REPLY"
	case OpDisconnectRequest:
		return "DISCONN REQUEST"
	case OpCommand:
		return "COMMAND"
	case OpPing:
		return "PING"
	case OpConnLimitReached:
		return "CONN LIMIT REACHED"
	case OpNotConnected:
		return "NOT CONNECTED"
	case OpMPsAreDead:
		return "MPS ARE DEAD"
	case OpAccessDenied:
		return "ACCESS DENIED"
	case OpConnectionFailed:
		return "CONNECTION FAILED"
	}
	return fmt.Sprintf("opcode %d", op)
}
