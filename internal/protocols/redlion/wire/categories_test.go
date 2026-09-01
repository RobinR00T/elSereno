package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"local/elsereno/internal/protocols/redlion/wire"
)

// cr3 builds a CR3 frame: length(BE) + reg(BE) + type(BE) + payload.
func cr3(reg uint16, t wire.PacketType, payload ...byte) []byte {
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[0:2], reg)
	binary.BigEndian.PutUint16(body[2:4], uint16(t))
	copy(body[4:], payload)
	frame := make([]byte, 2+len(body))
	// #nosec G115 -- body length fits uint16 in every test frame.
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
	copy(frame[2:], body)
	return frame
}

func TestClassifyType(t *testing.T) {
	reads := []wire.PacketType{wire.TypeMemRead, wire.TypePoll}
	for _, ty := range reads {
		if got := wire.ClassifyType(ty); got != wire.CategoryRead {
			t.Errorf("ClassifyType(0x%04x) = %v, want Read", ty, got)
		}
	}
	writes := []wire.PacketType{
		wire.TypeRegPush, wire.TypeValueWrite, wire.TypeValueWrite2,
		wire.TypeChunk, wire.TypeChunk2, wire.TypeChunk3,
	}
	for _, ty := range writes {
		if got := wire.ClassifyType(ty); got != wire.CategoryWrite {
			t.Errorf("ClassifyType(0x%04x) = %v, want Write", ty, got)
		}
	}
	// Handshake / no-payload / ambiguous opcodes must be Unknown
	// (fail-closed), NOT auto-passed as Read.
	unknown := []wire.PacketType{0x0100, 0x0200, 0x1000, 0x1600, 0x1800, 0x1c00, 0x1f00, 0x2e00, 0x9999}
	for _, ty := range unknown {
		if got := wire.ClassifyType(ty); got != wire.CategoryUnknown {
			t.Errorf("ClassifyType(0x%04x) = %v, want Unknown", ty, got)
		}
	}
}

// The config/firmware-mutating opcodes must never read as Read.
func TestClassifyType_SafetyInvariant(t *testing.T) {
	danger := []wire.PacketType{
		wire.TypeChunk, wire.TypeChunk2, wire.TypeChunk3,
		wire.TypeValueWrite, wire.TypeRegPush,
	}
	for _, ty := range danger {
		if wire.ClassifyType(ty) == wire.CategoryRead {
			t.Errorf("mutating opcode 0x%04x classified Read: write-through hole", ty)
		}
	}
}

func TestReadFrame_RoundTrip(t *testing.T) {
	frame := cr3(0x0042, wire.TypeChunk, 1, 2, 3, 4, 5)
	got, err := wire.ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, frame) {
		t.Fatalf("ReadFrame = %x, want %x", got, frame)
	}
	ty, ok := wire.ExtractType(got)
	if !ok || ty != wire.TypeChunk {
		t.Fatalf("ExtractType = 0x%04x, ok=%v", ty, ok)
	}
}

func TestReadFrame_ShortLength(t *testing.T) {
	// length field = 2 (< reg+type minimum of 4) -> ErrShortCR3Frame.
	frame := []byte{0x00, 0x02, 0x00, 0x00}
	_, err := wire.ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, wire.ErrShortCR3Frame) {
		t.Fatalf("err = %v, want ErrShortCR3Frame", err)
	}
}

func TestReadFrame_Truncated(t *testing.T) {
	// length says 8 body bytes but only 4 present -> io.ErrUnexpectedEOF.
	frame := []byte{0x00, 0x08, 0x00, 0x00, 0x15, 0x00}
	_, err := wire.ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrame_Sequential(t *testing.T) {
	a := cr3(0x0001, wire.TypeMemRead, 0, 0, 0, 0, 0, 0, 0, 0)
	b := cr3(0x0002, wire.TypeChunk, 9, 9)
	r := bytes.NewReader(append(a, b...))
	f1, err := wire.ReadFrame(r)
	if err != nil || !bytes.Equal(f1, a) {
		t.Fatalf("frame1 = %x err=%v", f1, err)
	}
	f2, err := wire.ReadFrame(r)
	if err != nil || !bytes.Equal(f2, b) {
		t.Fatalf("frame2 = %x err=%v", f2, err)
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add(cr3(0x0042, wire.TypeChunk, 1, 2, 3))
	f.Add([]byte{0x00, 0x02, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, buf []byte) {
		frame, err := wire.ReadFrame(bytes.NewReader(buf))
		if err != nil {
			return
		}
		ty, ok := wire.ExtractType(frame)
		if !ok {
			t.Fatalf("frame read but type not extractable: %x", frame)
		}
		switch wire.ClassifyType(ty) {
		case wire.CategoryRead, wire.CategoryWrite, wire.CategoryUnknown:
		default:
			t.Fatalf("ClassifyType out of range for 0x%04x", ty)
		}
	})
}
