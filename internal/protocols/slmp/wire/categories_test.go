package wire_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"local/elsereno/internal/protocols/slmp/wire"
)

// buildReq crafts a 3E-binary request carrying the given command
// (subcommand 0, no monitoring timeout) plus optional payload.
func buildReq(command uint16, payload ...byte) []byte {
	dataLen := 2 + 2 + 2 + len(payload) // monitoring + command + subcommand + payload
	frame := make([]byte, 9+dataLen)
	binary.LittleEndian.PutUint16(frame[0:2], wire.SubheaderRequestLE)
	frame[3] = 0xFF
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF)
	binary.LittleEndian.PutUint16(frame[7:9], uint16(dataLen))
	binary.LittleEndian.PutUint16(frame[11:13], command)
	copy(frame[15:], payload)
	return frame
}

func TestClassify(t *testing.T) {
	reads := []wire.Command{
		wire.CmdReadCPUModelName, wire.CmdDeviceReadBatch,
		wire.CmdDeviceReadRandom, wire.CmdDeviceReadBlock,
	}
	for _, c := range reads {
		if got := wire.Classify(c); got != wire.CategoryRead {
			t.Errorf("Classify(0x%04x) = %v, want CategoryRead", uint16(c), got)
		}
	}
	writes := []wire.Command{
		wire.CmdDeviceWriteBatch, wire.CmdDeviceWriteRandom, wire.CmdDeviceWriteBlock,
		wire.CmdRemoteRun, wire.CmdRemoteStop, wire.CmdRemotePause,
		wire.CmdRemoteLatchClear, wire.CmdRemoteReset,
	}
	for _, c := range writes {
		if got := wire.Classify(c); got != wire.CategoryWrite {
			t.Errorf("Classify(0x%04x) = %v, want CategoryWrite", uint16(c), got)
		}
	}
	for _, c := range []wire.Command{0x0000, 0x0402, 0x1400, 0x9999, 0xFFFF} {
		if got := wire.Classify(c); got != wire.CategoryUnknown {
			t.Errorf("Classify(0x%04x) = %v, want CategoryUnknown", uint16(c), got)
		}
	}
}

// TestClassify_ReadWriteDisjoint sweeps the command space and
// asserts the batch/random Write commands never read as Read.
func TestClassify_ReadWriteDisjoint(t *testing.T) {
	if wire.Classify(wire.CmdDeviceWriteBatch) == wire.CategoryRead {
		t.Fatal("Device Write Batch classified as Read: write-through hole")
	}
	for i := 0; i <= 0xFFFF; i++ {
		if wire.Classify(wire.Command(i)) == wire.CategoryRead {
			switch wire.Command(i) {
			case wire.CmdDeviceWriteBatch, wire.CmdDeviceWriteRandom,
				wire.CmdDeviceWriteBlock, wire.CmdRemoteRun, wire.CmdRemoteStop:
				t.Fatalf("command 0x%04x classified as both Read and a known write", i)
			}
		}
	}
}

func TestExtractCommand(t *testing.T) {
	// The command word sits at bytes 11..12, so a frame needs >= 13
	// bytes; 12 is too short.
	if _, ok := wire.ExtractCommand(make([]byte, 12)); ok {
		t.Error("ExtractCommand accepted a 12-byte frame (command needs 13)")
	}
	req := buildReq(uint16(wire.CmdDeviceWriteBatch))
	cmd, ok := wire.ExtractCommand(req)
	if !ok || cmd != wire.CmdDeviceWriteBatch {
		t.Fatalf("ExtractCommand = (0x%04x, %v), want Device Write Batch", uint16(cmd), ok)
	}
}

func TestReadFrame(t *testing.T) {
	a := buildReq(uint16(wire.CmdDeviceReadBatch), 0x01, 0x02, 0x03)
	b := buildReq(uint16(wire.CmdDeviceWriteBatch), 0xAA)
	stream := bytes.NewReader(append(append([]byte{}, a...), b...))

	got1, err := wire.ReadFrame(stream)
	if err != nil {
		t.Fatalf("ReadFrame #1: %v", err)
	}
	if !bytes.Equal(got1, a) {
		t.Fatalf("ReadFrame #1 = %x, want %x", got1, a)
	}
	got2, err := wire.ReadFrame(stream)
	if err != nil {
		t.Fatalf("ReadFrame #2: %v", err)
	}
	if !bytes.Equal(got2, b) {
		t.Fatalf("ReadFrame #2 = %x, want %x", got2, b)
	}
	if _, err := wire.ReadFrame(stream); err != io.EOF {
		t.Fatalf("ReadFrame at EOF = %v, want io.EOF", err)
	}

	// A truncated body is an error, not a partial frame.
	trunc := a[:len(a)-2]
	if _, err := wire.ReadFrame(bytes.NewReader(trunc)); err == nil {
		t.Fatal("ReadFrame accepted a truncated frame")
	}
}

func TestBuildRefusal(t *testing.T) {
	req := buildReq(uint16(wire.CmdDeviceWriteBatch), 0x00, 0x01)
	req[2] = 0x07 // network
	req[3] = 0x2A // PC
	r := wire.BuildRefusal(req)
	if len(r) != wire.HeaderLenResponse+2 {
		t.Fatalf("refusal length = %d, want %d", len(r), wire.HeaderLenResponse+2)
	}
	if binary.LittleEndian.Uint16(r[0:2]) != wire.SubheaderResponseLE {
		t.Errorf("refusal subheader = 0x%04x, want response marker", binary.LittleEndian.Uint16(r[0:2]))
	}
	if r[2] != 0x07 || r[3] != 0x2A {
		t.Errorf("refusal did not echo routing: net=0x%02x pc=0x%02x", r[2], r[3])
	}
	if ec := binary.LittleEndian.Uint16(r[9:11]); ec != wire.EndCodeRefused {
		t.Errorf("refusal end code = 0x%04x, want 0x%04x", ec, wire.EndCodeRefused)
	}
	if binary.LittleEndian.Uint16(r[9:11]) == 0x0000 {
		t.Error("refusal carries a success end code")
	}
}

func TestBuildRefusal_ShortInputDoesNotPanic(t *testing.T) {
	for _, short := range [][]byte{nil, {}, {0x50}, make([]byte, wire.HeaderLenRequest-1)} {
		r := wire.BuildRefusal(short)
		if len(r) != wire.HeaderLenResponse+2 {
			t.Fatalf("short-input refusal length = %d", len(r))
		}
		if binary.LittleEndian.Uint16(r[0:2]) != wire.SubheaderResponseLE {
			t.Error("short-input refusal lacks the response subheader")
		}
	}
}

// FuzzClassifyPipeline drives ExtractCommand -> Classify plus
// ReadFrame + BuildRefusal on arbitrary input: nothing may panic,
// ReadFrame must bound its allocation, and every refusal must be a
// well-formed SLMP response.
func FuzzClassifyPipeline(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildReq(uint16(wire.CmdDeviceReadBatch)))
	f.Add(buildReq(uint16(wire.CmdDeviceWriteBatch), 0x01, 0x02))
	f.Fuzz(func(t *testing.T, buf []byte) {
		if cmd, ok := wire.ExtractCommand(buf); ok {
			switch wire.Classify(cmd) {
			case wire.CategoryRead, wire.CategoryWrite, wire.CategoryUnknown:
			default:
				t.Fatalf("Classify out of range for 0x%04x", uint16(cmd))
			}
		}
		// ReadFrame must never panic on arbitrary bytes.
		_, _ = wire.ReadFrame(bytes.NewReader(buf))
		// BuildRefusal must be panic-free and well-formed.
		r := wire.BuildRefusal(buf)
		if len(r) != wire.HeaderLenResponse+2 {
			t.Fatalf("refusal length = %d", len(r))
		}
		if binary.LittleEndian.Uint16(r[9:11]) == 0x0000 {
			t.Fatal("refusal carries a success end code")
		}
	})
}
