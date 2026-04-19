//go:build offensive

package enip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	enipwire "local/elsereno/internal/protocols/enip/wire"
)

func TestBuild_SetAttributeSingle(t *testing.T) {
	r := Request{
		Op:            OpSetAttributeSingle,
		Target:        "10.0.0.1:44818",
		SessionHandle: 0xDEADBEEF,
		ClassID:       0x0001,
		InstanceID:    0x0001,
		AttributeID:   0x0007,
		Data:          []byte{0x00, 0x01},
	}
	b, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	cmd := binary.LittleEndian.Uint16(b[0:2])
	if cmd != enipwire.CmdSendRRData {
		t.Fatalf("cmd = 0x%04x, want SendRRData", cmd)
	}
	session := binary.LittleEndian.Uint32(b[4:8])
	if session != 0xDEADBEEF {
		t.Fatalf("session handle wrong")
	}
	// Service byte 0x10 (Set Attribute Single) must be present in
	// the MR portion.
	if !bytes.Contains(b, []byte{0x10}) {
		t.Fatalf("service byte missing")
	}
	if !bytes.Contains(b, r.Data) {
		t.Fatalf("data missing")
	}
}

func TestBuild_Reset(t *testing.T) {
	r := Request{Op: OpReset, Target: "x", SessionHandle: 1}
	b, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	// Service byte 0x05 (Reset) must be present.
	if !bytes.Contains(b, []byte{0x05}) {
		t.Fatalf("reset service byte missing")
	}
}

func TestBuild_BadOp(t *testing.T) {
	_, err := Build(Request{Op: "nope", Target: "x"})
	if !errors.Is(err, ErrBadOp) {
		t.Fatalf("want ErrBadOp, got %v", err)
	}
}

func TestMutationFor_Deterministic(t *testing.T) {
	r := Request{Op: OpReset, Target: "10.0.0.1:44818", SessionHandle: 1}
	m1, err := MutationFor(r)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := MutationFor(r)
	if m1.PayloadHash != m2.PayloadHash {
		t.Fatal("hash not deterministic")
	}
}
