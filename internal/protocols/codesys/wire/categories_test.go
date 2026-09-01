package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/codesys/wire"
)

func TestClassify(t *testing.T) {
	reads := []wire.Command{
		wire.MakeCommand(wire.SvcCmpDevice, 0x01),       // GetTargetIdent
		wire.MakeCommand(wire.SvcCmpApp, 0x14),          // ReadStatus
		wire.MakeCommand(wire.SvcCmpApp, 0x18),          // ReadAppList
		wire.MakeCommand(wire.SvcCmpIecVarAccess, 0x03), // ReadVarList
		wire.MakeCommand(wire.SvcCmpIecVarAccess, 0x05), // ReadVars
	}
	for _, c := range reads {
		if got := wire.ClassifyCommand(c); got != wire.CategoryRead {
			t.Errorf("Classify(%02x/%02x) = %v, want Read", c.Service(), c.Cmd(), got)
		}
	}
	writes := []wire.Command{
		wire.MakeCommand(wire.SvcCmpApp, 0x05),          // Download
		wire.MakeCommand(wire.SvcCmpApp, 0x11),          // Stop
		wire.MakeCommand(wire.SvcCmpApp, 0x12),          // Reset
		wire.MakeCommand(wire.SvcCmpDevice, 0x06),       // SetOperatingMode
		wire.MakeCommand(wire.SvcCmpIecVarAccess, 0x04), // WriteVarList
		wire.MakeCommand(wire.SvcCmpIecVarAccess, 0x06), // WriteVars
	}
	for _, c := range writes {
		if got := wire.ClassifyCommand(c); got != wire.CategoryWrite {
			t.Errorf("Classify(%02x/%02x) = %v, want Write", c.Service(), c.Cmd(), got)
		}
	}
	unknown := []wire.Command{
		wire.MakeCommand(0x99, 0x99),
		wire.MakeCommand(wire.SvcCmpApp, 0xFE),
		wire.MakeCommand(0x03, 0x01), // service 0x03 not mapped
	}
	for _, c := range unknown {
		if got := wire.ClassifyCommand(c); got != wire.CategoryUnknown {
			t.Errorf("Classify(%02x/%02x) = %v, want Unknown", c.Service(), c.Cmd(), got)
		}
	}
}

// TestClassify_SafetyInvariant: the dangerous mutations must never
// read as CategoryRead (auto-pass).
func TestClassify_SafetyInvariant(t *testing.T) {
	danger := []wire.Command{
		wire.MakeCommand(wire.SvcCmpApp, 0x05),          // Download
		wire.MakeCommand(wire.SvcCmpApp, 0x34),          // DownloadEncrypted
		wire.MakeCommand(wire.SvcCmpApp, 0x11),          // Stop
		wire.MakeCommand(wire.SvcCmpApp, 0x12),          // Reset
		wire.MakeCommand(wire.SvcCmpIecVarAccess, 0x06), // WriteVars
	}
	for _, c := range danger {
		if wire.ClassifyCommand(c) == wire.CategoryRead {
			t.Errorf("mutation %02x/%02x classified as Read: write-through hole", c.Service(), c.Cmd())
		}
	}
}

func TestMakeCommand_Roundtrip(t *testing.T) {
	c := wire.MakeCommand(0x02, 0x35)
	if c.Service() != 0x02 || c.Cmd() != 0x35 {
		t.Fatalf("roundtrip: service=%02x cmd=%02x", c.Service(), c.Cmd())
	}
}

func FuzzClassifyCommand(f *testing.F) {
	f.Add(uint16(0x0214))
	f.Add(uint16(0x0906))
	f.Fuzz(func(t *testing.T, v uint16) {
		switch wire.ClassifyCommand(wire.Command(v)) {
		case wire.CategoryRead, wire.CategoryWrite, wire.CategoryUnknown:
		default:
			t.Fatalf("Classify out of range for 0x%04x", v)
		}
	})
}
