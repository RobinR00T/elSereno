package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// CPStatus is the decoded "Get CP status response" (command 108).
// Offsets are from the start of the datagram, as checked on the
// capture (testdata/README.md).
type CPStatus struct {
	LoadIn       byte   `json:"load_in"`
	ModIn        byte   `json:"mod_in"`
	LoadState    byte   `json:"load_state"`
	SingleScan   byte   `json:"single_scan"`
	CPValid      byte   `json:"cp_valid"`
	KeyState     byte   `json:"key_state"`
	KeyName      string `json:"key_name"`
	RunState     byte   `json:"run_state"`
	RunName      string `json:"run_name"`
	ProjectMajor uint16 `json:"project_major"`
	ProjectMinor uint16 `json:"project_minor"`
	// ProjectTimestamp is the project download time (Unix seconds).
	ProjectTimestamp uint32 `json:"project_timestamp"`
	Project          string `json:"project"`
}

// Datagram offsets inside a CP status response.
const (
	offLoadIn     = 16
	offKeyState   = 21
	offRunState   = 22
	offMinor      = 72
	offMajor      = 74
	offTimestamp  = 76
	offProject    = 80
	projectLen    = 10
	minStatusSize = offProject + projectLen
)

// ParseCPStatus decodes a Get CP status response datagram (it calls
// Parse, so the CRC and lengths are checked first).
func ParseCPStatus(b []byte) (CPStatus, error) {
	f, err := Parse(b)
	if err != nil {
		return CPStatus{}, err
	}
	if f.Opcode != OpCommand || f.TS == nil || f.TS.Command != CmdCPStatusResponse {
		return CPStatus{}, ErrNotStatus
	}
	if len(f.raw) < minStatusSize {
		return CPStatus{}, ErrShort
	}
	r := f.raw
	s := CPStatus{
		LoadIn: r[offLoadIn], ModIn: r[offLoadIn+1], LoadState: r[offLoadIn+2],
		SingleScan: r[offLoadIn+3], CPValid: r[offLoadIn+4],
		KeyState: r[offKeyState], RunState: r[offRunState],
		ProjectMinor:     binary.LittleEndian.Uint16(r[offMinor:]),
		ProjectMajor:     binary.LittleEndian.Uint16(r[offMajor:]),
		ProjectTimestamp: binary.LittleEndian.Uint32(r[offTimestamp:]),
	}
	name := r[offProject : offProject+projectLen]
	if i := bytes.IndexByte(name, 0); i >= 0 {
		name = name[:i]
	}
	s.Project = string(name)
	s.KeyName = KeyStateName(s.KeyState)
	s.RunName = RunStateName(s.RunState)
	return s, nil
}

// KeyStateName names the controller key switch position. PROGRAM and
// REMOTE let a workstation change the safety program over the network;
// TRITON needed one of them.
func KeyStateName(k byte) string {
	switch k {
	case 0:
		return "STOP"
	case 1:
		return "PROGRAM"
	case 2:
		return "RUN"
	case 3:
		return "REMOTE"
	}
	return fmt.Sprintf("unknown (%d)", k)
}

// KeyAllowsChanges reports whether the key position accepts program or
// state changes from the network (PROGRAM or REMOTE).
func KeyAllowsChanges(k byte) bool { return k == 1 || k == 3 }

// RunStateName names the program run state.
func RunStateName(r byte) string {
	switch r {
	case 0:
		return "RUNNING"
	case 1:
		return "HALTED"
	case 2:
		return "PAUSED"
	}
	return fmt.Sprintf("unknown (%d)", r)
}

// commandNames covers the commands elSereno reports by name; the others
// print as their number.
var commandNames = map[byte]string{
	0: "Start download all", 1: "Start download change", 2: "Update configuration",
	3: "Upload configuration", 10: "End download all", 11: "End download change",
	13: "Attach TRICON", 19: "Get CP status", 20: "Run program", 21: "Halt program",
	22: "Pause program", 24: "Get chassis status", 27: "Set I/O point values",
	29: "Get MP status", 30: "Set retentive values", 55: "Allocate program",
	56: "Allocate function", 57: "Clear retentives", 65: "Upload program",
	66: "Upload function", 80: "Go to DOWNLOAD mode", 100: "Command rejected",
	101: "Download all permitted", 102: "Download change permitted",
	103: "Modification accepted", 106: "TRICON attached", 108: "Get CP status response",
	119: "Get chassis status response", 153: "Allocate program response",
	154: "Allocate function response", 162: "Upload program response",
	163: "Upload function response",
}

// CommandName names a TriStation command.
func CommandName(c byte) string {
	if n, ok := commandNames[c]; ok {
		return n
	}
	return fmt.Sprintf("command %d", c)
}

// changeCommands are workstation commands that change the controller's
// program, configuration, points or run state. A passive monitor flags
// them: on a safety controller each one is worth a look.
var changeCommands = map[byte]bool{
	0: true, 1: true, 2: true, 10: true, 11: true, 20: true, 21: true,
	22: true, 27: true, 30: true, 55: true, 56: true, 57: true, 80: true,
}

// IsChange reports whether a workstation command changes the controller.
func IsChange(c byte) bool { return changeCommands[c] }
