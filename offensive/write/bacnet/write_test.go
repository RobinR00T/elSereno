//go:build offensive

package bacnet

import (
	"bytes"
	"errors"
	"testing"
)

func TestBuild_WriteProperty(t *testing.T) {
	r := Request{
		Op:         OpWriteProperty,
		Target:     "10.0.0.1:47808",
		InvokeID:   0x07,
		ObjectType: ObjectAnalogValue,
		Instance:   0x01,
		PropertyID: 85, // Present-Value
		// Application tag 4 (Real), length 4, IEEE 754 = 32.0.
		Value: []byte{0x44, 0x42, 0x00, 0x00, 0x00},
	}
	b, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	// BVLC type 0x81, function 0x0A.
	if b[0] != 0x81 || b[1] != 0x0A {
		t.Fatalf("BVLC prefix wrong: % x", b[:2])
	}
	// NPDU control byte expects-reply = 0x04.
	if b[5] != 0x04 {
		t.Fatalf("NPDU control = 0x%02x", b[5])
	}
	// APDU service choice 0x0F (WriteProperty) at offset 9.
	if b[9] != 0x0F {
		t.Fatalf("service choice = 0x%02x, want 0x0F", b[9])
	}
	// Value must appear.
	if !bytes.Contains(b, r.Value) {
		t.Fatalf("value missing from packet")
	}
}

func TestBuild_BadOp(t *testing.T) {
	_, err := Build(Request{Op: "nope", Target: "x", Value: []byte{1}})
	if !errors.Is(err, ErrBadOp) {
		t.Fatalf("want ErrBadOp, got %v", err)
	}
}

func TestBuild_EmptyValue(t *testing.T) {
	_, err := Build(Request{Op: OpWriteProperty, Target: "x"})
	if !errors.Is(err, ErrEmptyValue) {
		t.Fatalf("want ErrEmptyValue, got %v", err)
	}
}

func TestBuild_InstanceTooLarge(t *testing.T) {
	_, err := Build(Request{Op: OpWriteProperty, Target: "x", Value: []byte{1}, Instance: 0x400000})
	if !errors.Is(err, ErrInstanceTooLarge) {
		t.Fatalf("want ErrInstanceTooLarge, got %v", err)
	}
}

func TestBuild_PropertyIDEncoding(t *testing.T) {
	// One-byte PID.
	r := Request{
		Op: OpWriteProperty, Target: "x",
		Value:      []byte{0x21, 0x01}, // app tag 2 (unsigned int) len=1 value=1
		ObjectType: ObjectBinaryValue, Instance: 5, PropertyID: 85,
	}
	b, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	// Two-byte PID path.
	r.PropertyID = 0x0123
	b2, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b2) != len(b)+1 {
		t.Fatalf("two-byte PID should add exactly one byte: %d vs %d", len(b2), len(b))
	}
}

func TestMutationFor_Deterministic(t *testing.T) {
	r := Request{
		Op: OpWriteProperty, Target: "10.0.0.1:47808",
		Value: []byte{0x21, 0x00}, ObjectType: ObjectDevice, Instance: 1, PropertyID: 85,
	}
	m1, err := MutationFor(r)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := MutationFor(r)
	if m1.PayloadHash != m2.PayloadHash {
		t.Fatal("hash not deterministic")
	}
}
