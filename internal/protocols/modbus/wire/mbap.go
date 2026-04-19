package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MBAPLen is the fixed Modbus Application Protocol header length.
const MBAPLen = 7

// ProtocolID is the fixed protocol identifier for classic Modbus.
const ProtocolID uint16 = 0x0000

// MaxPDULen is the spec cap for the PDU part of a Modbus/TCP message
// (MODBUS Messaging on TCP/IP V1.0b §3.2). 256 - (MBAP 7) + Unit 1 =
// 250; we use 253 which is the conventional operator-quoted ceiling
// that excludes the TCP overhead and includes the function code.
const MaxPDULen = 253

// ErrBadProtocol is returned when ProtocolID is non-zero.
var ErrBadProtocol = errors.New("modbus: non-zero protocol id")

// ErrLengthMismatch is returned when MBAP.Length disagrees with the
// observed PDU size.
var ErrLengthMismatch = errors.New("modbus: MBAP length mismatch")

// ErrPDUTooLong is returned when the PDU portion exceeds MaxPDULen.
var ErrPDUTooLong = errors.New("modbus: PDU exceeds 253 bytes")

// ErrShortFrame is returned when the buffer is smaller than MBAPLen.
var ErrShortFrame = errors.New("modbus: frame shorter than MBAP (7 bytes)")

// MBAP holds the parsed Modbus/TCP header.
type MBAP struct {
	TxID     uint16
	Protocol uint16
	Length   uint16 // bytes covering Unit + PDU
	Unit     uint8
}

// Frame is a parsed Modbus/TCP message.
type Frame struct {
	MBAP MBAP
	PDU  []byte // function code + data; always >= 1 byte when MBAP.Length >= 2
}

// ParseMBAP parses the 7-byte header without consuming a reader.
func ParseMBAP(b []byte) (MBAP, error) {
	if len(b) < MBAPLen {
		return MBAP{}, fmt.Errorf("%w: have %d", ErrShortFrame, len(b))
	}
	m := MBAP{
		TxID:     binary.BigEndian.Uint16(b[0:2]),
		Protocol: binary.BigEndian.Uint16(b[2:4]),
		Length:   binary.BigEndian.Uint16(b[4:6]),
		Unit:     b[6],
	}
	if m.Protocol != ProtocolID {
		return MBAP{}, fmt.Errorf("%w: 0x%04x", ErrBadProtocol, m.Protocol)
	}
	if m.Length < 2 {
		return MBAP{}, fmt.Errorf("%w: length=%d < 2 (Unit+FC)", ErrLengthMismatch, m.Length)
	}
	if int(m.Length) > MaxPDULen+1 { // +1 for Unit byte
		return MBAP{}, fmt.Errorf("%w: length=%d", ErrPDUTooLong, m.Length)
	}
	return m, nil
}

// MarshalMBAP writes m into a fixed 7-byte buffer.
func MarshalMBAP(m MBAP) [MBAPLen]byte {
	var out [MBAPLen]byte
	binary.BigEndian.PutUint16(out[0:2], m.TxID)
	binary.BigEndian.PutUint16(out[2:4], m.Protocol)
	binary.BigEndian.PutUint16(out[4:6], m.Length)
	out[6] = m.Unit
	return out
}

// ReadFrame reads one complete Modbus/TCP frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [MBAPLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, fmt.Errorf("modbus: header: %w", err)
	}
	m, err := ParseMBAP(hdr[:])
	if err != nil {
		return Frame{}, err
	}
	// Length includes Unit byte; PDU is Length - 1.
	pduLen := int(m.Length) - 1
	if pduLen < 1 || pduLen > MaxPDULen {
		return Frame{}, fmt.Errorf("%w: pdu len=%d", ErrPDUTooLong, pduLen)
	}
	pdu := make([]byte, pduLen)
	if _, err := io.ReadFull(r, pdu); err != nil {
		return Frame{}, fmt.Errorf("modbus: pdu: %w", err)
	}
	return Frame{MBAP: m, PDU: pdu}, nil
}

// WriteFrame writes the full Modbus/TCP frame to w.
func WriteFrame(w io.Writer, f Frame) error {
	if len(f.PDU) < 1 || len(f.PDU) > MaxPDULen {
		return fmt.Errorf("%w: pdu=%d", ErrPDUTooLong, len(f.PDU))
	}
	m := f.MBAP
	m.Protocol = ProtocolID
	// len(f.PDU) <= MaxPDULen (253) < 65535, safe widening to uint16.
	// #nosec G115 -- bounded above
	m.Length = uint16(len(f.PDU)) + 1 // +1 Unit byte
	hdr := MarshalMBAP(m)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(f.PDU); err != nil {
		return err
	}
	return nil
}

// FunctionCode returns the FC byte (first PDU byte), or 0 on empty
// PDU. Callers who need the exception bit check it with IsException
// on the raw byte.
func (f Frame) FunctionCode() FunctionCode {
	if len(f.PDU) == 0 {
		return 0
	}
	return FunctionCode(f.PDU[0] & 0x7f)
}

// IsExceptionFrame reports whether the frame encodes a Modbus
// exception (FC bit 7 set, one byte of exception code following).
func (f Frame) IsExceptionFrame() bool {
	return len(f.PDU) >= 2 && IsException(f.PDU[0])
}

// ExceptionCode returns the exception code for a Modbus exception
// frame. Returns (0, false) if the frame is not an exception or the
// PDU is malformed.
func (f Frame) ExceptionCode() (ExceptionCode, bool) {
	if !f.IsExceptionFrame() {
		return 0, false
	}
	return ExceptionCode(f.PDU[1]), true
}

// BuildReadCoilsRequest returns a minimal Read Coils request for a
// single coil at address 0; the smallest legal Modbus read.
func BuildReadCoilsRequest(txID uint16, unit uint8) Frame {
	pdu := []byte{byte(FCReadCoils), 0x00, 0x00, 0x00, 0x01}
	return Frame{
		MBAP: MBAP{TxID: txID, Protocol: ProtocolID, Unit: unit},
		PDU:  pdu,
	}
}

// BuildReadDeviceIDRequest returns a FC 43 sub-code 14 (Read Device
// Identification) request. ReadDevID level 0x01 returns Basic info:
// VendorName, ProductCode, MajorMinorRevision.
func BuildReadDeviceIDRequest(txID uint16, unit uint8) Frame {
	pdu := []byte{byte(FCEncapsulatedInterface), 0x0E, 0x01, 0x00}
	return Frame{
		MBAP: MBAP{TxID: txID, Protocol: ProtocolID, Unit: unit},
		PDU:  pdu,
	}
}

// DeviceIDObjects parses a successful FC 43/14 response and returns
// the map of object_id -> string for the objects carried in the PDU.
// The object catalog is (per MODBUS-IDA §6.21 table 12):
//
//	0x00 VendorName          0x03 VendorUrl
//	0x01 ProductCode         0x04 ProductName
//	0x02 MajorMinorRevision  0x05 ModelName
func DeviceIDObjects(pdu []byte) (map[byte]string, error) {
	// PDU layout:
	//  [0]=0x2B  [1]=0x0E  [2]=conformity  [3]=moreFollows
	//  [4]=nextObjectID [5]=numberOfObjects
	//  [6..]= (objID, objLen, objValue)*
	if len(pdu) < 7 || pdu[0] != byte(FCEncapsulatedInterface) || pdu[1] != 0x0E {
		return nil, fmt.Errorf("modbus: not a FC43/14 response")
	}
	n := int(pdu[5])
	out := make(map[byte]string, n)
	off := 6
	for i := 0; i < n; i++ {
		if off+2 > len(pdu) {
			return nil, fmt.Errorf("modbus: truncated FC43 response at object %d", i)
		}
		objID := pdu[off]
		objLen := int(pdu[off+1])
		if off+2+objLen > len(pdu) {
			return nil, fmt.Errorf("modbus: object %d length exceeds PDU", i)
		}
		out[objID] = string(pdu[off+2 : off+2+objLen])
		off += 2 + objLen
	}
	return out, nil
}
