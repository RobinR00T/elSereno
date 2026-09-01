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

import "bytes"

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

// ---- L7 stream location (write-gate framing) -----------------------
//
// CODESYS v3 has NO deterministic transport-layer length delimiters we
// can trust to locate the L7 service header: the reference dissector
// itself finds L3 by scanning for its 0xc5 magic, L4 by scanning a
// byte set, and L7 by scanning for the L7 protocol_id magic. A
// write-gate must therefore NOT try to parse L3/L4 (a length it
// misreads is a classifier bypass). Instead it scans the reassembled
// client->server byte stream for EVERY L7 service header and refuses
// the stream unless every located command is a read or an allowlisted
// write. Injecting a decoy read header cannot hide a real write: the
// real write header still carries the magic and is still located.
//
// Wire layout at an L7 header offset p (from processL7 in the
// dissector): protocol_id/magic buf(p,2) ; header_size buf(p+2,2) ;
// service_id buf(p+4,2) LE ; cmd_id buf(p+6,2) LE.

// l7Magics are the two known L7 protocol_id magics, in wire byte order
// (the dissector matches buf(i,2):uint() == 0x55cd or 0x7557).
var l7Magics = [][2]byte{{0x55, 0xcd}, {0x75, 0x57}}

// l7HeaderMin is the bytes needed past a magic to read service_id and
// cmd_id: magic(2)+header_size(2)+service_id(2)+cmd_id(2).
const l7HeaderMin = 8

// L7Command is one L7 service header located in a byte stream, already
// classified. Offset is its start (the magic position).
type L7Command struct {
	Offset int
	Cmd    Command
	Cat    Category
}

// matchMagic reports whether buf[i:] starts with an L7 magic.
func matchMagic(buf []byte, i int) bool {
	if i+2 > len(buf) {
		return false
	}
	for _, m := range l7Magics {
		if buf[i] == m[0] && buf[i+1] == m[1] {
			return true
		}
	}
	return false
}

// decodeL7 extracts the (service_id, cmd_id) at a magic offset p and
// classifies it. service_id / cmd_id are 16-bit LE on the wire but the
// mapped request services and commands all fit in a byte; a value with
// its high byte set is a response or malformed request, which we treat
// as CategoryUnknown (fail-closed) rather than truncating.
func decodeL7(buf []byte, p int) (Command, Category) {
	svc := uint16(buf[p+4]) | uint16(buf[p+5])<<8
	cmd := uint16(buf[p+6]) | uint16(buf[p+7])<<8
	if svc > 0xFF || cmd > 0xFF {
		return 0, CategoryUnknown
	}
	// #nosec G115 -- guarded above: svc,cmd <= 0xFF.
	c := MakeCommand(byte(svc), byte(cmd))
	return c, ClassifyCommand(c)
}

// magicPrefixAt reports whether buf[p:] is a (possibly partial) prefix
// of an L7 magic — i.e. once more of the stream arrives it could extend
// into a real header. This is what makes a lone trailing first-magic-
// byte (e.g. 0x55 with the 0xcd still in flight) unsafe to forward: a
// plain two-byte matchMagic would miss it and let a magic split across
// two reads slip through unclassified.
func magicPrefixAt(buf []byte, p int) bool {
	rem := len(buf) - p
	for _, m := range l7Magics {
		k := rem
		if k > len(m) {
			k = len(m)
		}
		if bytes.Equal(buf[p:p+k], m[:k]) {
			return true
		}
	}
	return false
}

// ScanL7 locates every fully-present L7 service header in buf and
// returns them classified, plus safeLen: the length of the leading run
// of buf the proxy may forward once every returned command is
// permitted. Bytes at/after safeLen may still be the start of an
// as-yet-incomplete header and must be held until more data arrives.
//
// safeLen holds back the last up-to-7 bytes whenever their suffix is a
// magic prefix — INCLUDING a single trailing 0x55/0x75 whose second
// magic byte has not arrived. Any magic starting in the final 7 bytes
// has an incomplete 8-byte header, so this covers every partial header;
// a magic that spans two reads can never be forwarded before it is
// classified. An incidental magic inside a payload only adds an extra
// command to classify (more conservative), it can never hide a real one.
func ScanL7(buf []byte) (cmds []L7Command, safeLen int) {
	for i := 0; i+l7HeaderMin <= len(buf); i++ {
		if !matchMagic(buf, i) {
			continue
		}
		c, cat := decodeL7(buf, i)
		cmds = append(cmds, L7Command{Offset: i, Cmd: c, Cat: cat})
	}
	safeLen = len(buf)
	start := len(buf) - (l7HeaderMin - 1)
	if start < 0 {
		start = 0
	}
	for p := start; p < len(buf); p++ {
		if magicPrefixAt(buf, p) {
			safeLen = p
			break
		}
	}
	return cmds, safeLen
}

// HasPartialL7Magic reports whether buf, from offset from onward, ends
// with the start of an L7 header that is not fully present (a truncated
// command at stream end). The proxy treats this as a refusal on EOF
// rather than forwarding a truncated command.
func HasPartialL7Magic(buf []byte, from int) bool {
	if from < 0 {
		from = 0
	}
	for i := from; i+2 <= len(buf); i++ {
		if matchMagic(buf, i) && i+l7HeaderMin > len(buf) {
			return true
		}
	}
	return false
}
