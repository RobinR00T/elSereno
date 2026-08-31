package wire

import (
	"encoding/binary"
	"io"
)

// Command is a MELSEC SLMP command code: the 16-bit little-endian
// value at bytes 11..12 of a 3E-binary request frame (after the
// 9-byte header + 2-byte monitoring timer). It is the classifier key
// for the proxy write-gating matrix (ADR-040). The subcommand
// (bytes 13..14) refines the addressing mode but never flips a read
// into a write, so it is not part of the category decision.
type Command uint16

// Well-known SLMP command codes (Mitsubishi Electric SLMP Reference
// Manual SH(NA)-080956ENG §3). Only the codes the classifier needs
// are named; anything outside the table is CategoryUnknown, which
// the proxy refuses (default-deny).
//
// SAFETY INVARIANT: the read set below must contain ONLY pure
// queries. Under-classifying a read as Unknown merely refuses it;
// over-classifying a mutating command as Read would open a
// write-through hole in the gate.
const (
	// Reads.
	CmdReadCPUModelName Command = 0x0101 // read (fingerprint)
	CmdDeviceReadBatch  Command = 0x0401 // read
	CmdDeviceReadRandom Command = 0x0403 // read
	CmdDeviceReadBlock  Command = 0x0601 // read

	// Writes (device memory).
	CmdDeviceWriteBatch  Command = 0x1401 // write
	CmdDeviceWriteRandom Command = 0x1402 // write
	CmdDeviceWriteBlock  Command = 0x1601 // write

	// Writes (CPU run-state control).
	CmdRemoteRun        Command = 0x1001 // write
	CmdRemoteStop       Command = 0x1002 // write
	CmdRemotePause      Command = 0x1003 // write
	CmdRemoteLatchClear Command = 0x1005 // write
	CmdRemoteReset      Command = 0x1006 // write
)

// Category groups SLMP commands for the proxy allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback for any command outside the
	// classifier. The proxy refuses it (default-deny).
	CategoryUnknown Category = iota
	// CategoryRead covers pure queries.
	CategoryRead
	// CategoryWrite covers every command that can mutate device
	// memory or CPU run-state.
	CategoryWrite
)

var readCommands = map[Command]struct{}{
	CmdReadCPUModelName: {},
	CmdDeviceReadBatch:  {},
	CmdDeviceReadRandom: {},
	CmdDeviceReadBlock:  {},
}

var writeCommands = map[Command]struct{}{
	CmdDeviceWriteBatch:  {},
	CmdDeviceWriteRandom: {},
	CmdDeviceWriteBlock:  {},
	CmdRemoteRun:         {},
	CmdRemoteStop:        {},
	CmdRemotePause:       {},
	CmdRemoteLatchClear:  {},
	CmdRemoteReset:       {},
}

// Classify returns the Category for an SLMP command. Commands in
// neither table return CategoryUnknown, which the proxy refuses.
func Classify(c Command) Category {
	if _, ok := readCommands[c]; ok {
		return CategoryRead
	}
	if _, ok := writeCommands[c]; ok {
		return CategoryWrite
	}
	return CategoryUnknown
}

// commandOffset is the byte offset of the 16-bit command within a
// 3E-binary request: 9-byte header + 2-byte monitoring timer.
const commandOffset = HeaderLenRequest + 2

// ExtractCommand recovers the command from a 3E-binary request
// frame. It returns (cmd, true) when the frame is long enough to
// carry the command word; (0, false) otherwise. It does not validate
// the subheader: the proxy only feeds it client-to-server frames,
// and a short frame classifies as Unknown and is refused.
func ExtractCommand(buf []byte) (Command, bool) {
	if len(buf) < commandOffset+2 {
		return 0, false
	}
	return Command(binary.LittleEndian.Uint16(buf[commandOffset : commandOffset+2])), true
}

// ReadFrame reads exactly one 3E-binary frame (request or response)
// from r. Both directions carry their byte count in the 2-byte
// data-length field at offset 7..8, and the total frame is
// HeaderLenRequest + that length, so a single reader serves both.
// The length is bounded by MaxResponseDataLength; an oversized field
// returns ErrLengthMismatch rather than allocating unbounded memory.
func ReadFrame(r io.Reader) ([]byte, error) {
	header := make([]byte, HeaderLenRequest)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	dataLen := int(binary.LittleEndian.Uint16(header[7:9]))
	if dataLen > MaxResponseDataLength {
		return nil, ErrLengthMismatch
	}
	frame := make([]byte, HeaderLenRequest+dataLen)
	copy(frame, header)
	if _, err := io.ReadFull(r, frame[HeaderLenRequest:]); err != nil {
		return nil, err
	}
	return frame, nil
}

// EndCodeRefused is the SLMP end code the proxy returns for a refused
// request: 0xC059, "the command/subcommand cannot be executed",
// which a real client reads as an intelligible rejection.
const EndCodeRefused uint16 = 0xC059

// BuildRefusal returns a 3E-binary response frame that refuses the
// given request with EndCodeRefused. It echoes the request routing
// bytes (network / PC / module IO / station) so a client correlates
// the refusal instead of seeing a mid-stream drop (ADR-040). A
// request shorter than the header yields a best-effort default-routed
// refusal rather than panicking.
func BuildRefusal(req []byte) []byte {
	out := make([]byte, HeaderLenResponse+2) // header + end code
	binary.LittleEndian.PutUint16(out[0:2], SubheaderResponseLE)
	if len(req) >= HeaderLenRequest {
		copy(out[2:7], req[2:7]) // network / PC / module-IO / station
	} else {
		out[3] = 0xFF // PC = CPU default
		binary.LittleEndian.PutUint16(out[4:6], 0x03FF)
	}
	binary.LittleEndian.PutUint16(out[7:9], 0x0002) // response data length = end code only
	binary.LittleEndian.PutUint16(out[9:11], EndCodeRefused)
	return out
}
