//go:build offensive

package s7

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestBuild_WriteVar(t *testing.T) {
	r := Request{
		Op:       OpWriteVar,
		Target:   "10.0.0.1:102",
		PDURef:   0x0102,
		Area:     0x84, // DB
		DBNumber: 1,
		Address:  0 << 3, // byte 0, bit 0
		Data:     []byte{0x01, 0x02, 0x03, 0x04},
	}
	b, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	// TPKT header.
	if b[0] != 0x03 || b[1] != 0x00 {
		t.Fatalf("TPKT version wrong: % x", b[:2])
	}
	total := binary.BigEndian.Uint16(b[2:4])
	if int(total) != len(b) {
		t.Fatalf("TPKT length %d != actual %d", total, len(b))
	}
	// Data is present at the tail.
	if !bytes.Contains(b, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Fatalf("payload data missing: % x", b)
	}
	// S7 magic + ROSCTR Job at offsets 7/8.
	if b[7] != 0x32 || b[8] != 0x01 {
		t.Fatalf("S7 magic/ROSCTR wrong: % x", b[7:9])
	}
	// Write function byte must be in the parameter area.
	if !bytes.Contains(b, []byte{paramWrite, 0x01}) {
		t.Fatalf("Write function not found")
	}
}

func TestBuild_PLCStop(t *testing.T) {
	b, err := Build(Request{Op: OpPLCStop, Target: "x", PDURef: 0x0001})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("P_PROGRAM")) {
		t.Fatalf("P_PROGRAM ident missing: % x", b)
	}
	if !bytes.Contains(b, []byte{paramPLCStop}) {
		t.Fatalf("Stop parameter missing")
	}
}

func TestBuild_PLCRestart(t *testing.T) {
	b, err := Build(Request{Op: OpPLCRestart, Target: "x", PDURef: 0x0001})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte{paramPLCCtl}) {
		t.Fatalf("PLC control parameter missing")
	}
}

func TestBuild_BadOp(t *testing.T) {
	_, err := Build(Request{Op: "nope", Target: "x"})
	if !errors.Is(err, ErrBadOp) {
		t.Fatalf("want ErrBadOp, got %v", err)
	}
}

func TestBuild_EmptyData(t *testing.T) {
	_, err := Build(Request{Op: OpWriteVar, Target: "x"})
	if !errors.Is(err, ErrEmptyPayload) {
		t.Fatalf("want ErrEmptyPayload, got %v", err)
	}
}

func TestBuild_TooMuchData(t *testing.T) {
	_, err := Build(Request{Op: OpWriteVar, Target: "x", Data: make([]byte, 300)})
	if !errors.Is(err, ErrDataTooLong) {
		t.Fatalf("want ErrDataTooLong, got %v", err)
	}
}

func TestMutationFor_Deterministic(t *testing.T) {
	r := Request{Op: OpPLCStop, Target: "10.0.0.1:102", PDURef: 7}
	m1, err := MutationFor(r)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := MutationFor(r)
	if m1.PayloadHash != m2.PayloadHash {
		t.Fatal("hash not deterministic")
	}
	if m1.Operation != string(OpPLCStop) || m1.Protocol != "s7" {
		t.Fatalf("wrong mutation: %+v", m1)
	}
}
