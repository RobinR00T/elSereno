package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/slmp/wire"
)

func TestBuildReadCPUModelNameFrameLayout(t *testing.T) {
	t.Parallel()
	got := wire.BuildReadCPUModelName()
	want := []byte{
		0x50, 0x00, // subheader (request, LE)
		0x00,       // network
		0xFF,       // PC
		0xFF, 0x03, // dest module IO (LE: 0x03FF)
		0x00,       // station
		0x06, 0x00, // request data length (LE: 6)
		0x00, 0x00, // monitoring timer
		0x01, 0x01, // command (LE: 0x0101)
		0x00, 0x00, // subcommand
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame mismatch:\n got=%x\nwant=%x", got, want)
	}
	if len(got) != 15 {
		t.Fatalf("frame length: got %d want 15", len(got))
	}
}

func TestParseReadCPUModelNameSuccess(t *testing.T) {
	t.Parallel()
	frame := buildResp(padQ03(), 0x4612)
	cpu, err := wire.ParseReadCPUModelName(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cpu.Model != "Q03UDVCPU" {
		t.Fatalf("Model: got %q", cpu.Model)
	}
	if cpu.CPUType != 0x4612 {
		t.Fatalf("CPUType: got 0x%04x", cpu.CPUType)
	}
}

func TestParseReadCPUModelNameTrimsNUL(t *testing.T) {
	t.Parallel()
	model := []byte("L26CPU-BT       ")
	model[10] = 0x00 // truncate-with-NUL midway through padding
	frame := buildResp(model, 0x4671)
	cpu, err := wire.ParseReadCPUModelName(frame)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cpu.Model != "L26CPU-BT" {
		t.Fatalf("Model trim: got %q", cpu.Model)
	}
}

func TestParseReadCPUModelNameRejectsShortFrame(t *testing.T) {
	t.Parallel()
	// Minimum sensible response is 11 bytes (9 header + 2 end
	// code). Anything shorter trips ErrShortFrame.
	for _, n := range []int{0, 5, 8, 10} {
		_, err := wire.ParseReadCPUModelName(make([]byte, n))
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestParseReadCPUModelNameRejectsBadSubheader(t *testing.T) {
	t.Parallel()
	frame := buildResp(padQ03(), 0x4612)
	frame[0] = 0x50 // request subheader
	frame[1] = 0x00
	_, err := wire.ParseReadCPUModelName(frame)
	if !errors.Is(err, wire.ErrNotResponse) {
		t.Fatalf("expected ErrNotResponse, got %v", err)
	}
}

func TestParseReadCPUModelNameRejectsLengthMismatch(t *testing.T) {
	t.Parallel()
	frame := buildResp(padQ03(), 0x4612)
	// Twiddle the data-length field to a too-large declared
	// length while the frame buffer stays the same.
	binary.LittleEndian.PutUint16(frame[7:9], 0x0064)
	_, err := wire.ParseReadCPUModelName(frame)
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("expected ErrLengthMismatch on length disagreement, got %v", err)
	}
}

func TestParseReadCPUModelNameRejectsAbsurdDeclaredLength(t *testing.T) {
	t.Parallel()
	frame := buildResp(padQ03(), 0x4612)
	// Declared length way past MaxResponseDataLength.
	binary.LittleEndian.PutUint16(frame[7:9], 0xFFFF)
	_, err := wire.ParseReadCPUModelName(frame)
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("expected ErrLengthMismatch on absurd declared length, got %v", err)
	}
}

func TestParseReadCPUModelNameRejectsNonZeroEndCode(t *testing.T) {
	t.Parallel()
	// Build a 13-byte error response (header + non-zero end code).
	frame := []byte{
		0xD0, 0x00,
		0x00, 0xFF,
		0xFF, 0x03,
		0x00,
		0x02, 0x00, // declared length 2 (just end code, no payload)
		0x55, 0xC0, // end code 0xC055 (example refusal code)
	}
	_, err := wire.ParseReadCPUModelName(frame)
	if !errors.Is(err, wire.ErrEndCodeNonZero) {
		t.Fatalf("expected ErrEndCodeNonZero, got %v", err)
	}
}

func TestParseReadCPUModelNameRejectsTruncatedSuccess(t *testing.T) {
	t.Parallel()
	// Header says success + declared length 20, but payload is
	// missing entirely. Caller already validated len >= 13 (the
	// header + end code), so this exercises the
	// declaredLen-vs-buffer-size disagreement after the end-code
	// branch.
	frame := []byte{
		0xD0, 0x00,
		0x00, 0xFF,
		0xFF, 0x03,
		0x00,
		0x14, 0x00, // declared length 20
		0x00, 0x00, // end code = success
		// payload missing — buffer is only 11 bytes total
	}
	_, err := wire.ParseReadCPUModelName(frame)
	if !errors.Is(err, wire.ErrLengthMismatch) {
		t.Fatalf("expected ErrLengthMismatch on truncated success, got %v", err)
	}
}

func TestIsResponseFrame(t *testing.T) {
	t.Parallel()
	resp := buildResp(padQ03(), 0x4612)
	if !wire.IsResponseFrame(resp) {
		t.Fatalf("expected IsResponseFrame true on a complete response")
	}
	req := wire.BuildReadCPUModelName()
	if wire.IsResponseFrame(req) {
		t.Fatalf("expected IsResponseFrame false on a request frame")
	}
	if wire.IsResponseFrame(nil) {
		t.Fatalf("nil should not be a response frame")
	}
	if wire.IsResponseFrame([]byte{0xD0}) {
		t.Fatalf("single byte too short to be a response frame")
	}
}

// buildResp produces a 29-byte success response with the given
// 16-byte model and 2-byte CPU type. End code is always 0x0000;
// the error-frame tests hand-roll their own buffers inline.
func buildResp(model16 []byte, cpuType uint16) []byte {
	if len(model16) != 16 {
		panic("buildResp: model must be 16 bytes")
	}
	frame := make([]byte, 29)
	binary.LittleEndian.PutUint16(frame[0:2], 0x00D0)
	frame[2] = 0x00
	frame[3] = 0xFF
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF)
	frame[6] = 0x00
	binary.LittleEndian.PutUint16(frame[7:9], 0x0014) // declared length: 20
	binary.LittleEndian.PutUint16(frame[9:11], 0x0000)
	copy(frame[11:27], model16)
	binary.LittleEndian.PutUint16(frame[27:29], cpuType)
	return frame
}

// padQ03 returns the 16-byte ASCII model "Q03UDVCPU" right-padded
// with 0x20. Most success-path tests use this canonical model.
func padQ03() []byte {
	const s = "Q03UDVCPU"
	b := make([]byte, 16)
	copy(b, s)
	for i := len(s); i < 16; i++ {
		b[i] = 0x20
	}
	return b
}
