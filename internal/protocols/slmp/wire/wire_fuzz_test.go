package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/slmp/wire"
)

// FuzzParseReadCPUModelName asserts that ParseReadCPUModelName
// never panics on arbitrary input and that, on success, the
// 16-byte Model field has no TRAILING NUL or space (trimASCII's
// contract). Embedded NULs are intentionally preserved so the
// parser doesn't silently splice attacker-controlled input
// across a NUL boundary.
func FuzzParseReadCPUModelName(f *testing.F) {
	f.Add([]byte{})
	// 11-byte minimal response (header + end code) — should
	// trip ErrShortFrame.
	f.Add([]byte{
		0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
	})
	// 29-byte success response with Q03UDVCPU.
	full := []byte{
		0xD0, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00, 0x14, 0x00, 0x00, 0x00,
	}
	full = append(full, []byte("Q03UDVCPU       ")...)
	full = append(full, 0x12, 0x46)
	f.Add(full)
	f.Fuzz(func(t *testing.T, buf []byte) {
		cpu, err := wire.ParseReadCPUModelName(buf)
		if err != nil {
			return
		}
		if cpu.Model == "" {
			return
		}
		last := cpu.Model[len(cpu.Model)-1]
		if last == 0x00 || last == ' ' {
			t.Fatalf("trimASCII left trailing NUL/space in Model=%q", cpu.Model)
		}
	})
}

// FuzzBuildReadCPUModelNameStable asserts the builder is a
// constant 15-byte frame regardless of fuzz input (it takes
// no parameters but we drive a discard byte to satisfy the
// fuzz signature).
func FuzzBuildReadCPUModelNameStable(f *testing.F) {
	f.Add(byte(0x00))
	f.Fuzz(func(t *testing.T, _ byte) {
		got := wire.BuildReadCPUModelName()
		if len(got) != 15 {
			t.Fatalf("frame length: got %d want 15", len(got))
		}
	})
}
