package wire_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

func TestBuildReadLongStatus_Layout(t *testing.T) {
	frame := wire.BuildReadLongStatus()
	if len(frame) != wire.MailboxLen {
		t.Fatalf("len = %d, want %d", len(frame), wire.MailboxLen)
	}
	if frame[0] != wire.TypeRequest {
		t.Errorf("byte[0] = 0x%02x, want 0x02 (request)", frame[0])
	}
	if frame[42] != wire.ServiceLongStatus {
		t.Errorf("byte[42] = 0x%02x, want 0x21 (Read Long Status)", frame[42])
	}
	if frame[43] != 0x01 || frame[44] != 0x03 || frame[45] != 0x01 {
		t.Errorf("bytes[43..45] = 0x%02x 0x%02x 0x%02x, want 01 03 01",
			frame[43], frame[44], frame[45])
	}
	// Reserved bytes must be zero.
	for _, idx := range []int{1, 5, 10, 41, 46, 55} {
		if frame[idx] != 0 {
			t.Errorf("reserved byte[%d] = 0x%02x, want 0", idx, frame[idx])
		}
	}
}

func TestParseLongStatus_ModelAndFirmware(t *testing.T) {
	// Synthesise a 56-byte response with a model + firmware
	// tag embedded in the middle.
	frame := make([]byte, wire.MailboxLen)
	frame[0] = wire.TypeResponse
	copy(frame[16:], []byte("PACSystems V12.45.7"))

	info := wire.ParseLongStatus(frame)
	if info.Model == "" {
		t.Fatal("Model not extracted")
	}
	if !strings.HasPrefix(info.Model, "PACSystems") {
		t.Errorf("Model = %q, want PACSystems-prefixed", info.Model)
	}
	if info.Firmware != "V12.45.7" {
		t.Errorf("Firmware = %q, want V12.45.7", info.Firmware)
	}
}

func TestParseLongStatus_ModelOnly(t *testing.T) {
	// Model run must be ≥ 5 chars to satisfy the v1.21 chunk-4
	// extractor's anti-noise floor. "PACSystems" is 10 chars +
	// a canonical prefix; perfect for this test.
	frame := make([]byte, wire.MailboxLen)
	frame[0] = wire.TypeResponse
	copy(frame[16:], []byte("PACSystems"))
	info := wire.ParseLongStatus(frame)
	if info.Model != "PACSystems" {
		t.Errorf("Model = %q, want PACSystems", info.Model)
	}
	if info.Firmware != "" {
		t.Errorf("Firmware = %q, want empty (no version tag)", info.Firmware)
	}
}

func TestParseLongStatus_NoMarker(t *testing.T) {
	frame := make([]byte, wire.MailboxLen)
	frame[0] = wire.TypeResponse
	// Random non-printable bytes — no marker anywhere.
	for i := 1; i < len(frame); i++ {
		frame[i] = byte(i & 0x7F)
	}
	info := wire.ParseLongStatus(frame)
	if info.Model != "" {
		t.Errorf("Model = %q, want empty for no-marker buffer", info.Model)
	}
	if info.Firmware != "" {
		t.Errorf("Firmware = %q, want empty", info.Firmware)
	}
}

func TestParseLongStatus_ShortBuffer(t *testing.T) {
	info := wire.ParseLongStatus([]byte{0x03, 0x00})
	if info.Model != "" || info.Firmware != "" {
		t.Errorf("short buffer should produce empty info, got %+v", info)
	}
}

func TestParseLongStatus_ICCodeAndFirmware(t *testing.T) {
	// IC695 (RX3i) family — firmware tag right after the model.
	frame := make([]byte, wire.MailboxLen)
	frame[0] = wire.TypeResponse
	copy(frame[18:], []byte("\x00\x00IC695CPE330\x00V9.30"))
	info := wire.ParseLongStatus(frame)
	if !strings.HasPrefix(info.Model, "IC695") {
		t.Errorf("Model = %q, want IC695-prefix", info.Model)
	}
	if info.Firmware != "V9.30" {
		t.Errorf("Firmware = %q, want V9.30", info.Firmware)
	}
}

func TestExtractFirmwareTag_RejectsTooShort(t *testing.T) {
	// "V0" / "V1" runs are too noisy to be useful. The extractor
	// rejects anything <4 chars.
	frame := make([]byte, wire.MailboxLen)
	frame[0] = wire.TypeResponse
	copy(frame[18:], []byte("PACSystems V1"))
	info := wire.ParseLongStatus(frame)
	if info.Firmware != "" {
		t.Errorf("Firmware = %q, want empty (V1 is too short)", info.Firmware)
	}
}
