package wire

// CODESYS v3 service classification for the proxy write-gating matrix
// (ADR-040).
//
// SOURCE: the (service_id, cmd_id) map below is taken from the public
// fridgebuyer/codesys3-dissector Wireshark dissector (validated
// against its sample pcaps) and the Rapid7 "Deep Dive into Reversing
// CODESYS" research, not guesswork. A CODESYS v3 request is a layered
// L3 (router) / L4 (channel) / L7 (service) structure; the classifier
// key is the L7 (service_id, cmd_id) pair. Locating that pair inside a
// raw TCP frame requires parsing the L3 + L4 headers (variable length,
// with L4 reassembly) — that framing lands with the WriteGatedHandler;
// this file is the validated category map it consumes.

// Command packs the L7 service id (high byte) and command id (low
// byte) into the classifier key.
type Command uint16

// MakeCommand builds a Command from a CODESYS service id + command id.
func MakeCommand(service, cmd byte) Command { return Command(uint16(service)<<8 | uint16(cmd)) }

// Service returns the L7 service id.
func (c Command) Service() byte { return byte(c >> 8) }

// Cmd returns the L7 command id.
func (c Command) Cmd() byte { return byte(c & 0xFF) }

// Service ids named for readability (dissector §getL7CmdName).
const (
	SvcCmpDevice       byte = 0x01 // CmpDevice: session + device mgmt
	SvcCmpApp          byte = 0x02 // CmpApp: application lifecycle
	SvcCmpIecVarAccess byte = 0x09 // CmpIecVarAccess: variable read/write
)

// Category groups CODESYS commands for the proxy allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback; the proxy refuses it.
	CategoryUnknown Category = iota
	// CategoryRead covers session/handshake ops and pure queries —
	// nothing that mutates control state, application code, variables,
	// or run state.
	CategoryRead
	// CategoryWrite covers downloads, variable writes, run/stop,
	// reset, forces, breakpoints, operating-mode changes, and app
	// lifecycle mutations.
	CategoryWrite
)

// readCommands is the deliberately-audited auto-pass set: session and
// query operations that do NOT mutate the controller. SAFETY
// INVARIANT: no command here may change application code, variables,
// force state, breakpoints, operating mode, or run state.
var readCommands = map[Command]struct{}{
	// CmpDevice: handshake + status.
	MakeCommand(SvcCmpDevice, 0x01): {}, // GetTargetIdent
	MakeCommand(SvcCmpDevice, 0x02): {}, // Login
	MakeCommand(SvcCmpDevice, 0x03): {}, // Logout
	MakeCommand(SvcCmpDevice, 0x05): {}, // EchoService
	MakeCommand(SvcCmpDevice, 0x07): {}, // GetOperatingMode
	MakeCommand(SvcCmpDevice, 0x08): {}, // InteractiveLogin
	MakeCommand(SvcCmpDevice, 0x0a): {}, // SessionCreate
	MakeCommand(SvcCmpDevice, 0x0b): {}, // ResetOriginGetConfig
	// CmpApp: login + read-only introspection.
	MakeCommand(SvcCmpApp, 0x01): {}, // Login
	MakeCommand(SvcCmpApp, 0x02): {}, // Logout
	MakeCommand(SvcCmpApp, 0x14): {}, // ReadStatus
	MakeCommand(SvcCmpApp, 0x16): {}, // ReadCallStack
	MakeCommand(SvcCmpApp, 0x17): {}, // GetAreaOffset
	MakeCommand(SvcCmpApp, 0x18): {}, // ReadAppList
	MakeCommand(SvcCmpApp, 0x21): {}, // UploadForceList (reads forces out)
	MakeCommand(SvcCmpApp, 0x25): {}, // ReadAppStateList
	MakeCommand(SvcCmpApp, 0x28): {}, // CheckFileConsistency
	MakeCommand(SvcCmpApp, 0x29): {}, // ReadAppInfo
	MakeCommand(SvcCmpApp, 0x31): {}, // ReadProjectInfo
	MakeCommand(SvcCmpApp, 0x33): {}, // ReadFlowValues
	MakeCommand(SvcCmpApp, 0x35): {}, // ReadAppContent
	MakeCommand(SvcCmpApp, 0x38): {}, // GetAreaAddress
	// CmpIecVarAccess: variable-list registration + reads.
	MakeCommand(SvcCmpIecVarAccess, 0x01): {}, // RegisterVarList
	MakeCommand(SvcCmpIecVarAccess, 0x02): {}, // UnRegisterVarList
	MakeCommand(SvcCmpIecVarAccess, 0x03): {}, // ReadVarList
	MakeCommand(SvcCmpIecVarAccess, 0x05): {}, // ReadVars
}

// writeCommands are the well-known mutating operations. Membership
// here is for intelligible audit; anything not in readCommands is
// refused regardless.
var writeCommands = map[Command]struct{}{
	// CmpDevice control.
	MakeCommand(SvcCmpDevice, 0x04): {}, // ResetOrigin
	MakeCommand(SvcCmpDevice, 0x06): {}, // SetOperatingMode
	MakeCommand(SvcCmpDevice, 0x09): {}, // RenameNode
	// CmpApp mutations.
	MakeCommand(SvcCmpApp, 0x03): {}, // CreateApp
	MakeCommand(SvcCmpApp, 0x04): {}, // DeleteApp
	MakeCommand(SvcCmpApp, 0x05): {}, // Download
	MakeCommand(SvcCmpApp, 0x06): {}, // OnlineChange
	MakeCommand(SvcCmpApp, 0x07): {}, // DeviceDownload
	MakeCommand(SvcCmpApp, 0x08): {}, // CreateDevApp
	MakeCommand(SvcCmpApp, 0x10): {}, // Start
	MakeCommand(SvcCmpApp, 0x11): {}, // Stop
	MakeCommand(SvcCmpApp, 0x12): {}, // Reset
	MakeCommand(SvcCmpApp, 0x13): {}, // SetBP
	MakeCommand(SvcCmpApp, 0x15): {}, // DeleteBP
	MakeCommand(SvcCmpApp, 0x19): {}, // SetNextStatement
	MakeCommand(SvcCmpApp, 0x20): {}, // ReleaseForceList
	MakeCommand(SvcCmpApp, 0x22): {}, // SingleCycle
	MakeCommand(SvcCmpApp, 0x23): {}, // CreateBootProject
	MakeCommand(SvcCmpApp, 0x24): {}, // ReInitApp
	MakeCommand(SvcCmpApp, 0x26): {}, // LoadBootApp
	MakeCommand(SvcCmpApp, 0x27): {}, // RegisterBootApp
	MakeCommand(SvcCmpApp, 0x30): {}, // DownloadCompact
	MakeCommand(SvcCmpApp, 0x32): {}, // DefineFlow
	MakeCommand(SvcCmpApp, 0x34): {}, // DownloadEncrypted
	MakeCommand(SvcCmpApp, 0x36): {}, // SaveRetains
	MakeCommand(SvcCmpApp, 0x37): {}, // RestoreRetains
	// CmpIecVarAccess writes.
	MakeCommand(SvcCmpIecVarAccess, 0x04): {}, // WriteVarList
	MakeCommand(SvcCmpIecVarAccess, 0x06): {}, // WriteVars
}

// ClassifyCommand returns the Category for an L7 command. Commands in
// neither table return CategoryUnknown, which the proxy refuses. (The
// package already has a fingerprint-level Classify(buf) for banner
// detection; this is the write-gate command classifier.)
func ClassifyCommand(c Command) Category {
	if _, ok := readCommands[c]; ok {
		return CategoryRead
	}
	if _, ok := writeCommands[c]; ok {
		return CategoryWrite
	}
	return CategoryUnknown
}
