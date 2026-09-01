package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/finsudp/wire"
)

func TestClassify(t *testing.T) {
	reads := []wire.Command{
		wire.CmdMemoryAreaRead, wire.CmdMemoryAreaMultipleRead,
		wire.CmdParameterAreaRead, wire.CmdControllerDataRead,
		wire.CmdControllerStatusRead, wire.CmdClockRead, wire.CmdErrorRead,
	}
	for _, c := range reads {
		if got := wire.Classify(c); got != wire.CategoryRead {
			t.Errorf("Classify(0x%04x) = %v, want CategoryRead", uint16(c), got)
		}
	}

	writes := []wire.Command{
		wire.CmdMemoryAreaWrite, wire.CmdMemoryAreaFill, wire.CmdMemoryAreaTransfer,
		wire.CmdParameterAreaWrite, wire.CmdParameterAreaClear,
		wire.CmdProgramAreaWrite, wire.CmdProgramAreaClear,
		wire.CmdRun, wire.CmdStop, wire.CmdClockWrite,
		wire.CmdAccessRightAcquire, wire.CmdAccessRightForceAcquire,
		wire.CmdAccessRightRelease, wire.CmdErrorClear,
		wire.CmdForcedSetReset, wire.CmdForcedSetResetCancel,
	}
	for _, c := range writes {
		if got := wire.Classify(c); got != wire.CategoryWrite {
			t.Errorf("Classify(0x%04x) = %v, want CategoryWrite", uint16(c), got)
		}
	}

	// Unknown / reserved codes default to refuse.
	for _, c := range []wire.Command{0x0000, 0x0199, 0x9999, 0x0403, 0xFFFF} {
		if got := wire.Classify(c); got != wire.CategoryUnknown {
			t.Errorf("Classify(0x%04x) = %v, want CategoryUnknown", uint16(c), got)
		}
	}
}

// TestClassify_NoWriteMasqueradesAsRead is the security-invariant
// guard: no command the classifier calls Read may sit in the write
// table, and Memory Area Write (the canonical dangerous command)
// must never read as CategoryRead.
func TestClassify_NoWriteMasqueradesAsRead(t *testing.T) {
	if wire.Classify(wire.CmdMemoryAreaWrite) == wire.CategoryRead {
		t.Fatal("Memory Area Write classified as Read: write-through hole")
	}
	// Sweep the whole command space; a command may be Read XOR Write,
	// never both (the maps must be disjoint).
	for i := 0; i <= 0xFFFF; i++ {
		c := wire.Command(i)
		cat := wire.Classify(c)
		if cat == wire.CategoryRead {
			// A read must not also be a known write. Re-deriving via
			// the packed code keeps the test independent of the maps.
			switch c {
			case wire.CmdMemoryAreaWrite, wire.CmdMemoryAreaFill,
				wire.CmdMemoryAreaTransfer, wire.CmdRun, wire.CmdStop,
				wire.CmdForcedSetReset:
				t.Fatalf("command 0x%04x classified as both Read and a known mutation", i)
			default:
				// Other read-classified commands are fine.
			}
		}
	}
}

func TestExtractCommand(t *testing.T) {
	// Too short: header (10) but no MRC/SRC.
	if _, ok := wire.ExtractCommand(make([]byte, wire.HeaderLen)); ok {
		t.Error("ExtractCommand accepted a frame with no MRC/SRC")
	}
	if _, ok := wire.ExtractCommand([]byte{0x80}); ok {
		t.Error("ExtractCommand accepted a 1-byte frame")
	}

	// A Memory Area Write request: header + 0x01 0x02.
	req := []byte{
		0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2A,
		0x01, 0x02,
	}
	cmd, ok := wire.ExtractCommand(req)
	if !ok {
		t.Fatal("ExtractCommand rejected a valid frame")
	}
	if cmd != wire.CmdMemoryAreaWrite {
		t.Fatalf("ExtractCommand = 0x%04x, want CmdMemoryAreaWrite", uint16(cmd))
	}
	if cmd.MRC() != 0x01 || cmd.SRC() != 0x02 {
		t.Fatalf("MRC/SRC = 0x%02x/0x%02x, want 0x01/0x02", cmd.MRC(), cmd.SRC())
	}
}

func TestBuildRefusal(t *testing.T) {
	req := []byte{
		0x80, 0x00, 0x02, // ICF RSV GCT
		0x10, 0x11, 0x12, // DNA DA1 DA2 (destination)
		0x20, 0x21, 0x22, // SNA SA1 SA2 (source)
		0x2A,       // SID
		0x01, 0x02, // MRC SRC (Memory Area Write)
	}
	r := wire.BuildRefusal(req)
	if len(r) != wire.HeaderLen+4 {
		t.Fatalf("refusal length = %d, want %d", len(r), wire.HeaderLen+4)
	}
	if r[0]&0x40 == 0 {
		t.Errorf("refusal ICF 0x%02x lacks the response bit", r[0])
	}
	// Routing swapped: response destination = request source.
	if r[3] != 0x20 || r[4] != 0x21 || r[5] != 0x22 {
		t.Errorf("response destination = %02x%02x%02x, want 202122 (req source)", r[3], r[4], r[5])
	}
	if r[6] != 0x10 || r[7] != 0x11 || r[8] != 0x12 {
		t.Errorf("response source = %02x%02x%02x, want 101112 (req destination)", r[6], r[7], r[8])
	}
	if r[9] != 0x2A {
		t.Errorf("SID echo = 0x%02x, want 0x2A", r[9])
	}
	if r[10] != 0x01 || r[11] != 0x02 {
		t.Errorf("MRC/SRC echo = 0x%02x/0x%02x, want 0x01/0x02", r[10], r[11])
	}
	// End code 0x2101 = cannot write / write-protected.
	if r[12] != 0x21 || r[13] != 0x01 {
		t.Errorf("end code = 0x%02x%02x, want 0x2101", r[12], r[13])
	}
	// A real client must be able to tell this is a refusal (end code
	// != 0x0000).
	if r[12] == 0x00 && r[13] == 0x00 {
		t.Error("refusal carries a success end code")
	}
}

func TestBuildRefusal_ShortInputDoesNotPanic(t *testing.T) {
	for _, short := range [][]byte{nil, {}, {0x80}, make([]byte, wire.HeaderLen-1), make([]byte, wire.HeaderLen)} {
		r := wire.BuildRefusal(short)
		if len(r) != wire.HeaderLen+4 {
			t.Fatalf("short-input refusal length = %d, want %d", len(r), wire.HeaderLen+4)
		}
		if r[0]&0x40 == 0 {
			t.Errorf("short-input refusal lacks the response bit")
		}
	}
}

// FuzzClassifyPipeline drives the whole request-side pipeline
// (ExtractCommand -> Classify -> BuildRefusal) on arbitrary input.
// Per ADR-040 the classifier must never panic and must default to
// refuse; every refusal frame must be a well-formed FINS response.
func FuzzClassifyPipeline(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02})
	f.Add([]byte{0x80, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, buf []byte) {
		cmd, ok := wire.ExtractCommand(buf)
		if ok {
			// A recovered command must classify without panicking and
			// only ever land in one of the three buckets.
			switch wire.Classify(cmd) {
			case wire.CategoryRead, wire.CategoryWrite, wire.CategoryUnknown:
			default:
				t.Fatalf("Classify returned an out-of-range category for 0x%04x", uint16(cmd))
			}
		}
		// BuildRefusal must be panic-free and well-formed for ANY
		// input, valid or not.
		r := wire.BuildRefusal(buf)
		if len(r) != wire.HeaderLen+4 {
			t.Fatalf("refusal length = %d, want %d", len(r), wire.HeaderLen+4)
		}
		if r[0]&0x40 == 0 {
			t.Fatalf("refusal ICF 0x%02x lacks the response bit", r[0])
		}
		if r[len(r)-2] == 0x00 && r[len(r)-1] == 0x00 {
			t.Fatal("refusal carries a success end code")
		}
	})
}
