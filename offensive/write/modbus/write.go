//go:build offensive

package modbus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
)

// Op identifies the write operation being performed.
type Op string

// Write operations supported in F5. FC 22 (Mask Write Register) and
// FC 23 (Read/Write Multiple Registers) are intentionally excluded
// from this initial set; they land in F6 with per-device risk notes.
// Names contain "register" which gosec's G101 regex flags as a
// potential credential literal — they are Modbus PDU operation
// labels, not secrets. The gosec directive below disarms that rule
// for this block only.
//
//nolint:gosec // G101 false positive — op labels
const (
	OpWriteSingleCoil        Op = "write_single_coil"        // FC 5
	OpWriteSingleRegister    Op = "write_single_register"    // FC 6
	OpWriteMultipleCoils     Op = "write_multiple_coils"     // FC 15
	OpWriteMultipleRegisters Op = "write_multiple_registers" // FC 16
)

// Request is a single-unit mutation. The caller fills exactly one of
// SingleCoilValue / SingleRegisterValue / MultipleCoilValues /
// MultipleRegisterValues to match Op.
type Request struct {
	Op      Op
	Target  string // host:port; used for confirm.Mutation.Target verbatim
	Unit    uint8
	TxID    uint16
	Address uint16
	// One-of:
	SingleCoilValue        bool
	SingleRegisterValue    uint16
	MultipleCoilValues     []bool
	MultipleRegisterValues []uint16
}

// Errors returned by Build and Execute.
var (
	ErrBadOp        = errors.New("modbus-write: unknown op")
	ErrEmptyPayload = errors.New("modbus-write: payload empty for op")
	ErrTooManyCoils = errors.New("modbus-write: FC15 capped at 1968 coils")
	ErrTooManyRegs  = errors.New("modbus-write: FC16 capped at 123 registers")
)

// Build returns the Modbus frame that Execute would send. Exposed for
// dry-run and for the dedicated test suite. Build MUST NOT perform
// any I/O.
func Build(r Request) (mbwire.Frame, error) {
	switch r.Op {
	case OpWriteSingleCoil:
		return buildSingleCoil(r), nil
	case OpWriteSingleRegister:
		return buildSingleRegister(r), nil
	case OpWriteMultipleCoils:
		return buildMultipleCoils(r)
	case OpWriteMultipleRegisters:
		return buildMultipleRegisters(r)
	default:
		return mbwire.Frame{}, fmt.Errorf("%w: %q", ErrBadOp, r.Op)
	}
}

func frame(r Request, pdu []byte) mbwire.Frame {
	return mbwire.Frame{
		MBAP: mbwire.MBAP{TxID: r.TxID, Protocol: mbwire.ProtocolID, Unit: r.Unit},
		PDU:  pdu,
	}
}

func buildSingleCoil(r Request) mbwire.Frame {
	on := [2]byte{0x00, 0x00}
	if r.SingleCoilValue {
		on = [2]byte{0xFF, 0x00}
	}
	pdu := []byte{
		byte(mbwire.FCWriteSingleCoil),
		byte(r.Address >> 8), byte(r.Address & 0xFF),
		on[0], on[1],
	}
	return frame(r, pdu)
}

func buildSingleRegister(r Request) mbwire.Frame {
	pdu := []byte{
		byte(mbwire.FCWriteSingleRegister),
		byte(r.Address >> 8), byte(r.Address & 0xFF),
		byte(r.SingleRegisterValue >> 8), byte(r.SingleRegisterValue & 0xFF),
	}
	return frame(r, pdu)
}

func buildMultipleCoils(r Request) (mbwire.Frame, error) {
	n := len(r.MultipleCoilValues)
	if n == 0 {
		return mbwire.Frame{}, ErrEmptyPayload
	}
	if n > 1968 {
		return mbwire.Frame{}, ErrTooManyCoils
	}
	byteCount := (n + 7) / 8
	bits := make([]byte, byteCount)
	for i, v := range r.MultipleCoilValues {
		if v {
			bits[i/8] |= 1 << (uint(i) & 7)
		}
	}
	// bounded: n <= 1968, so byteCount <= 246 fits in uint8.
	// #nosec G115
	pdu := []byte{
		byte(mbwire.FCWriteMultipleCoils),
		byte(r.Address >> 8), byte(r.Address & 0xFF),
		byte(uint16(n) >> 8), byte(uint16(n) & 0xFF),
		byte(byteCount),
	}
	pdu = append(pdu, bits...)
	return frame(r, pdu), nil
}

func buildMultipleRegisters(r Request) (mbwire.Frame, error) {
	n := len(r.MultipleRegisterValues)
	if n == 0 {
		return mbwire.Frame{}, ErrEmptyPayload
	}
	if n > 123 {
		return mbwire.Frame{}, ErrTooManyRegs
	}
	// #nosec G115 -- bounded
	byteCount := uint8(n * 2)
	pdu := make([]byte, 0, 6+int(byteCount))
	// #nosec G115
	pdu = append(pdu,
		byte(mbwire.FCWriteMultipleRegisters),
		byte(r.Address>>8), byte(r.Address&0xFF),
		byte(uint16(n)>>8), byte(uint16(n)&0xFF),
		byteCount,
	)
	for _, v := range r.MultipleRegisterValues {
		pdu = append(pdu, byte(v>>8), byte(v&0xFF))
	}
	return frame(r, pdu), nil
}

// MutationFor constructs the confirm.Mutation record for r. The payload
// hash is the SHA-256 of the built PDU (deterministic given r).
func MutationFor(r Request) (confirm.Mutation, error) {
	frame, err := Build(r)
	if err != nil {
		return confirm.Mutation{}, err
	}
	h := sha256.Sum256(frame.PDU)
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "modbus",
		Operation:   string(r.Op),
		Target:      r.Target,
		PayloadHash: h,
	}, nil
}

// Execute authorises r, dials the target, sends the write, and returns
// the parsed response or an exception code. A denial from Authorize
// is returned as-is; the caller uses errors.Is(err, confirm.ErrXxx).
func Execute(
	ctx context.Context,
	r Request,
	c confirm.Confirm,
	deriver confirm.KeyDeriver,
	auditor confirm.Auditor,
	dialTimeout, ioTimeout time.Duration,
) (mbwire.Frame, error) {
	m, err := MutationFor(r)
	if err != nil {
		return mbwire.Frame{}, err
	}
	if err := confirm.Authorize(ctx, m, c, deriver, auditor); err != nil {
		return mbwire.Frame{}, err
	}
	frame, err := Build(r)
	if err != nil {
		return mbwire.Frame{}, err
	}
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", r.Target)
	if err != nil {
		return mbwire.Frame{}, fmt.Errorf("modbus-write: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(ioTimeout))
	return sendOn(conn, frame)
}

// sendOn is the I/O half of Execute, split out so tests can drive it
// over net.Pipe() without a real TCP listener.
func sendOn(rw io.ReadWriter, frame mbwire.Frame) (mbwire.Frame, error) {
	if err := mbwire.WriteFrame(rw, frame); err != nil {
		return mbwire.Frame{}, fmt.Errorf("modbus-write: send: %w", err)
	}
	resp, err := mbwire.ReadFrame(rw)
	if err != nil {
		return mbwire.Frame{}, fmt.Errorf("modbus-write: recv: %w", err)
	}
	if ec, isEx := resp.ExceptionCode(); isEx {
		return resp, fmt.Errorf("modbus-write: exception 0x%02x", uint8(ec))
	}
	return resp, nil
}

// marshalUint16 is a tiny helper so Build reads naturally without
// repeating binary.BigEndian across every PDU.
func marshalUint16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

// Keep the helper referenced so the compiler does not flag it as dead
// when the writer path decides to use it directly. Kept simple for
// future FC22 (Mask Write) which has a richer PDU shape.
var _ = marshalUint16
