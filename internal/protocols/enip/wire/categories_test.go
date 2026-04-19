package wire

import (
	"encoding/binary"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		cmd  uint16
		want Category
	}{
		{CmdListIdentity, CategoryRead},
		{CmdListServices, CategoryRead},
		{CmdListInterfaces, CategoryRead},
		{CmdRegisterSession, CategoryRead},
		{CmdUnregisterSess, CategoryRead},
		{CmdSendRRData, CategoryWrite},
		{CmdSendUnitData, CategoryWrite},
		{0xBEEF, CategoryUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.cmd); got != c.want {
			t.Errorf("Classify(0x%04x) = %d, want %d", c.cmd, got, c.want)
		}
	}
}

func TestBuildRefusal_EchoesSessionAndContext(t *testing.T) {
	req := Header{
		Command:       CmdSendRRData,
		SessionHandle: 0xDEADBEEF,
		SenderContext: [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Options:       0x00000000,
	}
	out := BuildRefusal(req)
	if len(out) != HeaderLen {
		t.Fatalf("len=%d, want %d", len(out), HeaderLen)
	}
	if cmd := binary.LittleEndian.Uint16(out[0:2]); cmd != CmdSendRRData {
		t.Fatalf("cmd=0x%04x", cmd)
	}
	if st := binary.LittleEndian.Uint32(out[8:12]); st != 0x00000001 {
		t.Fatalf("status=0x%x, want 0x1", st)
	}
	if binary.LittleEndian.Uint32(out[4:8]) != 0xDEADBEEF {
		t.Fatalf("session handle mismatch")
	}
	for i := 0; i < 8; i++ {
		if out[12+i] != req.SenderContext[i] {
			t.Fatalf("context byte %d differ", i)
		}
	}
}
