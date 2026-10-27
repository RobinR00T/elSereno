package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// Real datagrams from malware_exec.pcap (testdata/README.md).
const (
	capConnectRequest    = "0100000001fc"
	capConnectReply      = "0200000001b8"
	capDisconnectRequest = "040000000130"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cpStatusResponse(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/cp_status_response.hex")
	if err != nil {
		t.Fatal(err)
	}
	return mustHex(t, strings.TrimSpace(string(b)))
}

func TestBuilders_MatchCapture(t *testing.T) {
	if got := hex.EncodeToString(BuildConnect()); got != capConnectRequest {
		t.Errorf("BuildConnect = %s, capture %s", got, capConnectRequest)
	}
	if got := hex.EncodeToString(BuildDisconnect()); got != capDisconnectRequest {
		t.Errorf("BuildDisconnect = %s, capture %s", got, capDisconnectRequest)
	}
	// Get CP status, seq 0, as sent by the engineering workstation.
	want := "05000a000000130000002700" + "0a00" + "5010"
	if got := hex.EncodeToString(BuildGetCPStatus(0)); got != want {
		t.Errorf("BuildGetCPStatus = %s, capture %s", got, want)
	}
}

func TestParse_ConnectReply(t *testing.T) {
	// The capture pads the 6-byte reply to the Ethernet minimum.
	b := append(mustHex(t, capConnectReply), make([]byte, 12)...)
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.Opcode != OpConnectReply || f.TS != nil {
		t.Errorf("frame = %+v", f)
	}
}

func TestParse_CPStatusResponse(t *testing.T) {
	f, err := Parse(cpStatusResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	if f.Opcode != OpCommand || f.TS == nil || f.TS.Command != CmdCPStatusResponse || f.TS.Path != 1 {
		t.Fatalf("frame = %+v ts=%+v", f, f.TS)
	}
	if !f.TS.ChecksumOK || f.TS.Length != 196 || len(f.Data) != 186 {
		t.Errorf("ts = %+v data=%d", f.TS, len(f.Data))
	}
	s, err := ParseCPStatus(cpStatusResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	if s.Project != "NOZOMI" || s.KeyName != "PROGRAM" || s.RunName != "RUNNING" ||
		s.ProjectMajor != 2 || s.ProjectMinor != 0 || s.ProjectTimestamp != 1521186298 || s.CPValid != 1 {
		t.Errorf("status = %+v", s)
	}
	if !KeyAllowsChanges(s.KeyState) {
		t.Error("PROGRAM must allow changes")
	}
}

func TestParse_Errors(t *testing.T) {
	good := cpStatusResponse(t)
	bad := bytes.Clone(good)
	bad[30] ^= 0xFF
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"short":     {[]byte{1, 0, 0}, ErrShort},
		"truncated": {good[:50], ErrLength},
		"crc":       {bad, ErrBadCRC},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(c.in); !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
	if _, err := ParseCPStatus(mustHex(t, capConnectReply)); !errors.Is(err, ErrNotStatus) {
		t.Errorf("ParseCPStatus(connect reply) = %v", err)
	}
}

func TestNames(t *testing.T) {
	if OpcodeName(OpConnectReply) != "CONNECT REPLY" || OpcodeName(200) != "opcode 200" {
		t.Error("OpcodeName")
	}
	if CommandName(55) != "Allocate program" || CommandName(250) != "command 250" {
		t.Error("CommandName")
	}
	if !IsChange(CmdAllocateProgram) || IsChange(CmdGetCPStatus) {
		t.Error("IsChange")
	}
	for k, n := range map[byte]string{0: "STOP", 1: "PROGRAM", 2: "RUN", 3: "REMOTE", 9: "unknown (9)"} {
		if KeyStateName(k) != n {
			t.Errorf("KeyStateName(%d)", k)
		}
	}
	for r, n := range map[byte]string{0: "RUNNING", 1: "HALTED", 2: "PAUSED", 7: "unknown (7)"} {
		if RunStateName(r) != n {
			t.Errorf("RunStateName(%d)", r)
		}
	}
	if _, err := BuildCommand(1, 0, make([]byte, 0x10000)); err == nil {
		t.Error("oversized command accepted")
	}
}
