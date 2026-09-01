package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/codesys/wire"
)

// l7 builds a minimal L7 service header: magic + header_size(0) +
// service_id(LE) + cmd_id(LE) + optional trailing payload.
func l7(service, cmd byte, magic [2]byte, payload ...byte) []byte {
	b := []byte{magic[0], magic[1], 0x00, 0x00, service, 0x00, cmd, 0x00}
	return append(b, payload...)
}

var (
	magicA = [2]byte{0x55, 0xcd}
	magicB = [2]byte{0x75, 0x57}
)

func TestScanL7_SingleRead(t *testing.T) {
	buf := l7(wire.SvcCmpApp, 0x14, magicA) // ReadStatus
	cmds, safeLen := wire.ScanL7(buf)
	if len(cmds) != 1 {
		t.Fatalf("cmds=%d, want 1", len(cmds))
	}
	if cmds[0].Cat != wire.CategoryRead {
		t.Errorf("cat=%v, want Read", cmds[0].Cat)
	}
	if safeLen != len(buf) {
		t.Errorf("safeLen=%d, want %d", safeLen, len(buf))
	}
}

func TestScanL7_WriteLocated(t *testing.T) {
	// A different service (CmpIecVarAccess/WriteVars) than the rest of
	// the file, so the classifier's per-service path is exercised too.
	buf := l7(wire.SvcCmpIecVarAccess, 0x06, magicB) // WriteVars
	cmds, _ := wire.ScanL7(buf)
	if len(cmds) != 1 || cmds[0].Cat != wire.CategoryWrite {
		t.Fatalf("want one Write, got %+v", cmds)
	}
	if cmds[0].Cmd != wire.MakeCommand(wire.SvcCmpIecVarAccess, 0x06) {
		t.Errorf("cmd=%04x", cmds[0].Cmd)
	}
}

// A decoy read header injected before a real write must NOT hide the
// write: ScanL7 locates both.
func TestScanL7_DecoyCannotHideWrite(t *testing.T) {
	decoy := l7(wire.SvcCmpApp, 0x14, magicA)       // ReadStatus (decoy)
	realw := l7(wire.SvcCmpApp, 0x11, magicA, 1, 2) // Stop (write)
	buf := append(append([]byte(nil), decoy...), realw...)
	cmds, _ := wire.ScanL7(buf)
	sawWrite := false
	for _, c := range cmds {
		if c.Cat == wire.CategoryWrite {
			sawWrite = true
		}
	}
	if !sawWrite {
		t.Fatalf("write header hidden by decoy: cmds=%+v", cmds)
	}
}

// A magic whose 8-byte header is not fully present pins safeLen at the
// magic and is not classified yet.
func TestScanL7_PartialHeaderHeld(t *testing.T) {
	full := l7(wire.SvcCmpApp, 0x14, magicA)
	buf := append(append([]byte(nil), full...), magicA[0], magicA[1], 0x00) // partial second header
	cmds, safeLen := wire.ScanL7(buf)
	if len(cmds) != 1 {
		t.Fatalf("cmds=%d, want 1 (partial not decoded)", len(cmds))
	}
	if safeLen != len(full) {
		t.Errorf("safeLen=%d, want %d (hold from partial magic)", safeLen, len(full))
	}
	if !wire.HasPartialL7Magic(buf, 0) {
		t.Errorf("HasPartialL7Magic=false, want true")
	}
}

// service_id / cmd_id with a high byte set (a response or malformed
// request) must classify Unknown, never Read.
func TestScanL7_HighByteIsUnknown(t *testing.T) {
	// service_id = 0x0102 (high byte set) -> unknown.
	buf := []byte{magicA[0], magicA[1], 0, 0, 0x02, 0x01, 0x14, 0x00}
	cmds, _ := wire.ScanL7(buf)
	if len(cmds) != 1 || cmds[0].Cat != wire.CategoryUnknown {
		t.Fatalf("want Unknown for high-byte service, got %+v", cmds)
	}
}

// A lone trailing first-magic-byte (0x55 with the 0xcd still in flight)
// must be HELD, not forwarded — otherwise a magic split across two
// reads slips through unclassified (a write-gate bypass).
func TestScanL7_LoneMagicFirstByteHeld(t *testing.T) {
	full := l7(wire.SvcCmpApp, 0x14, magicA)
	buf := append(append([]byte(nil), full...), magicA[0]) // + lone 0x55
	cmds, safeLen := wire.ScanL7(buf)
	if len(cmds) != 1 {
		t.Fatalf("cmds=%d, want 1 (the completed first header)", len(cmds))
	}
	if safeLen != len(full) {
		t.Fatalf("safeLen=%d, want %d (hold the lone 0x55)", safeLen, len(full))
	}
}

// The other magic's first byte (0x75) must be held too.
func TestScanL7_LoneMagicBFirstByteHeld(t *testing.T) {
	buf := []byte{0x00, 0x00, magicB[0]} // trailing lone 0x75
	_, safeLen := wire.ScanL7(buf)
	if safeLen != 2 {
		t.Fatalf("safeLen=%d, want 2 (hold the lone 0x75)", safeLen)
	}
}

// A trailing byte that is NOT a magic prefix is safe to forward.
func TestScanL7_NonMagicTailForwards(t *testing.T) {
	buf := []byte{0x00, 0x11, 0x22, 0x55, 0x99} // 0x55 followed by 0x99 (not 0xcd)
	_, safeLen := wire.ScanL7(buf)
	if safeLen != len(buf) {
		t.Fatalf("safeLen=%d, want %d (0x55 0x99 is not a magic)", safeLen, len(buf))
	}
}

func TestScanL7_NoMagicNoCommands(t *testing.T) {
	buf := bytes.Repeat([]byte{0x00, 0x11, 0x22}, 20)
	cmds, safeLen := wire.ScanL7(buf)
	if len(cmds) != 0 {
		t.Errorf("cmds=%d, want 0", len(cmds))
	}
	if safeLen != len(buf) {
		t.Errorf("safeLen=%d, want %d", safeLen, len(buf))
	}
}

func FuzzScanL7(f *testing.F) {
	f.Add(l7(wire.SvcCmpApp, 0x14, magicA))
	f.Add(l7(wire.SvcCmpApp, 0x05, magicB))
	f.Add([]byte{0x55, 0xcd, 0x00})
	f.Fuzz(func(t *testing.T, buf []byte) {
		cmds, safeLen := wire.ScanL7(buf)
		if safeLen < 0 || safeLen > len(buf) {
			t.Fatalf("safeLen %d out of range for len %d", safeLen, len(buf))
		}
		for _, c := range cmds {
			if c.Offset < 0 || c.Offset+8 > len(buf) {
				t.Fatalf("offset %d out of range for len %d", c.Offset, len(buf))
			}
			switch c.Cat {
			case wire.CategoryRead, wire.CategoryWrite, wire.CategoryUnknown:
			default:
				t.Fatalf("cat out of range: %v", c.Cat)
			}
		}
	})
}
