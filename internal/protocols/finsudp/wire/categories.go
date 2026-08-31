package wire

// Command is a FINS command code: the (MRC, SRC) pair carried at
// bytes 10..11 of a FINS/UDP frame (immediately after the 10-byte
// header). It is packed MRC<<8 | SRC and used as the classifier key
// for the proxy write-gating matrix (ADR-040).
type Command uint16

// MakeCommand packs a Main + Sub request code into a Command.
func MakeCommand(mrc, src byte) Command { return Command(uint16(mrc)<<8 | uint16(src)) }

// MRC returns the Main Request Code byte.
func (c Command) MRC() byte { return byte(c >> 8) }

// SRC returns the Sub Request Code byte.
func (c Command) SRC() byte { return byte(c & 0xFF) }

// Well-known FINS command codes (Omron CPU manual W421, FINS
// Commands Reference §5). Only the codes the classifier needs are
// named; anything outside the table is CategoryUnknown, which the
// proxy refuses (default-deny posture).
//
// SAFETY INVARIANT: the read set below must contain ONLY pure
// queries. Under-classifying a read as Unknown merely refuses it
// (safe, if inconvenient); over-classifying a mutating command as
// Read would open a write-through hole in the gate. When in doubt,
// leave a command out of the read set and let it default to refuse.
const (
	// Memory Area (MRC 0x01).
	CmdMemoryAreaRead         Command = 0x0101 // read
	CmdMemoryAreaWrite        Command = 0x0102 // write
	CmdMemoryAreaFill         Command = 0x0103 // write (fill a range)
	CmdMemoryAreaMultipleRead Command = 0x0104 // read
	CmdMemoryAreaTransfer     Command = 0x0105 // write (copy area to area)

	// Parameter Area (MRC 0x02).
	CmdParameterAreaRead  Command = 0x0201 // read
	CmdParameterAreaWrite Command = 0x0202 // write
	CmdParameterAreaClear Command = 0x0203 // write

	// Program Area (MRC 0x03).
	CmdProgramAreaWrite Command = 0x0307 // write
	CmdProgramAreaClear Command = 0x0308 // write

	// Run/Stop (MRC 0x04): operating-mode control, always mutating.
	CmdRun  Command = 0x0401 // write (switch to MONITOR/RUN)
	CmdStop Command = 0x0402 // write (switch to PROGRAM)

	// Controller Data / Status (MRC 0x05 / 0x06): pure reads.
	CmdControllerDataRead   Command = 0x0501 // read
	CmdControllerStatusRead Command = 0x0601 // read

	// Time (MRC 0x07).
	CmdClockRead  Command = 0x0701 // read
	CmdClockWrite Command = 0x0702 // write

	// Access Rights (MRC 0x0C): lock/unlock the CPU. Acquiring the
	// write lock is itself a mutation of device availability.
	CmdAccessRightAcquire      Command = 0x0C01 // write
	CmdAccessRightForceAcquire Command = 0x0C02 // write
	CmdAccessRightRelease      Command = 0x0C03 // write

	// Error log (MRC 0x21).
	CmdErrorClear Command = 0x2101 // write (clear the CPU error log)
	CmdErrorRead  Command = 0x2102 // read

	// Forced Set/Reset (MRC 0x23): force I/O bits on/off. Directly
	// drives physical outputs, so always mutating.
	CmdForcedSetReset       Command = 0x2301 // write
	CmdForcedSetResetCancel Command = 0x2302 // write
)

// Category groups FINS commands for the proxy allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback for any command outside the
	// classifier. The proxy refuses it (default-deny).
	CategoryUnknown Category = iota
	// CategoryRead covers pure queries that cannot mutate device
	// memory, program, run-state, clock, forced bits, or access
	// rights.
	CategoryRead
	// CategoryWrite covers every command that can mutate the device.
	CategoryWrite
)

// readCommands is the exhaustive, deliberately-minimal set of FINS
// commands that classify as CategoryRead. Membership here is the
// single security-sensitive decision in this file (see the SAFETY
// INVARIANT above): every entry must be a pure query.
var readCommands = map[Command]struct{}{
	CmdMemoryAreaRead:         {},
	CmdMemoryAreaMultipleRead: {},
	CmdParameterAreaRead:      {},
	CmdControllerDataRead:     {},
	CmdControllerStatusRead:   {},
	CmdClockRead:              {},
	CmdErrorRead:              {},
}

// writeCommands are the well-known mutating commands. Membership
// here is NOT security-sensitive (anything not in readCommands is
// already refused); it exists so the proxy can emit an intelligible
// "known write, refused" audit line rather than "unknown command".
var writeCommands = map[Command]struct{}{
	CmdMemoryAreaWrite:         {},
	CmdMemoryAreaFill:          {},
	CmdMemoryAreaTransfer:      {},
	CmdParameterAreaWrite:      {},
	CmdParameterAreaClear:      {},
	CmdProgramAreaWrite:        {},
	CmdProgramAreaClear:        {},
	CmdRun:                     {},
	CmdStop:                    {},
	CmdClockWrite:              {},
	CmdAccessRightAcquire:      {},
	CmdAccessRightForceAcquire: {},
	CmdAccessRightRelease:      {},
	CmdErrorClear:              {},
	CmdForcedSetReset:          {},
	CmdForcedSetResetCancel:    {},
}

// Classify returns the Category for a FINS command. Commands in
// neither table return CategoryUnknown, which the proxy treats as
// refuse.
func Classify(c Command) Category {
	if _, ok := readCommands[c]; ok {
		return CategoryRead
	}
	if _, ok := writeCommands[c]; ok {
		return CategoryWrite
	}
	return CategoryUnknown
}

// ExtractCommand recovers the (MRC, SRC) command from a FINS/UDP
// request datagram. It returns (cmd, true) when the datagram is at
// least header+MRC+SRC long; (0, false) otherwise. It does not
// validate the ICF/routing bytes: the proxy only ever feeds it
// client-to-server frames, and a malformed short frame classifies
// as Unknown and is refused.
func ExtractCommand(buf []byte) (Command, bool) {
	if len(buf) < HeaderLen+2 {
		return 0, false
	}
	return MakeCommand(buf[HeaderLen], buf[HeaderLen+1]), true
}

// BuildRefusal returns a FINS/UDP response datagram that refuses the
// given request with end code 0x2101 ("cannot write: area is
// read-only / write-protected", W421 §5.1.3), the protocol-native
// signal closest to "the proxy declined this write". The response
// echoes the request SID + MRC/SRC and swaps the source/destination
// routing bytes so a real client correlates the refusal instead of
// seeing a mid-stream drop (ADR-040).
//
// A request shorter than the 10-byte header yields a best-effort
// all-zero-routed refusal rather than panicking.
func BuildRefusal(req []byte) []byte {
	// End code: MRES 0x21 (cannot write) / SRES 0x01 (read-only /
	// write-protected area).
	const endMRES, endSRES = 0x21, 0x01

	out := make([]byte, 0, HeaderLen+4)
	out = append(out, ICFResponse, 0x00, 0x02) // ICF / RSV / GCT

	if len(req) >= HeaderLen {
		// Swap routing so the reply is addressed back to the caller:
		// response destination = request source, and vice versa.
		out = append(out, req[6], req[7], req[8]) // DNA/DA1/DA2 <- req SNA/SA1/SA2
		out = append(out, req[3], req[4], req[5]) // SNA/SA1/SA2 <- req DNA/DA1/DA2
		out = append(out, req[9])                 // SID echo
	} else {
		out = append(out, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00)
	}

	if len(req) >= HeaderLen+2 {
		out = append(out, req[HeaderLen], req[HeaderLen+1]) // MRC/SRC echo
	} else {
		out = append(out, 0x00, 0x00)
	}

	out = append(out, endMRES, endSRES) // end code
	return out
}
