package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/melsoft/wire"
)

func TestBuildGetCPUInfo(t *testing.T) {
	t.Parallel()
	got := wire.BuildGetCPUInfo()
	if len(got) != 41 {
		t.Fatalf("request length: got %d want 41", len(got))
	}
	if got[0] != wire.RequestMarker {
		t.Fatalf("request marker: got 0x%02x want 0x%02x", got[0], wire.RequestMarker)
	}
	// Returned slice must be a copy (mutating it must not affect the next call).
	got[0] = 0x00
	if wire.BuildGetCPUInfo()[0] != wire.RequestMarker {
		t.Fatal("BuildGetCPUInfo leaked its backing array")
	}
}

func TestParseCPUInfo(t *testing.T) {
	t.Parallel()
	// A valid response marker + a model at the reference offset.
	resp := make([]byte, wire.MinResponseLen)
	resp[0] = wire.ResponseMarker
	resp[1] = 0x00
	copy(resp[wire.ModelOffset:], []byte("Q03UDECPU       ")) // 16 bytes, space-padded
	info, err := wire.ParseCPUInfo(resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Model != "Q03UDECPU" {
		t.Fatalf("model: got %q want %q", info.Model, "Q03UDECPU")
	}
}

func TestParseCPUInfoValidMarkerShort(t *testing.T) {
	t.Parallel()
	// Valid marker but too short for a model: positive ID, empty model, no error.
	info, err := wire.ParseCPUInfo([]byte{wire.ResponseMarker, 0x00, 0x01, 0x02})
	if err != nil {
		t.Fatalf("a valid short marker must not error: %v", err)
	}
	if info.Model != "" {
		t.Fatalf("model: got %q want empty", info.Model)
	}
}

func TestParseCPUInfoRejects(t *testing.T) {
	t.Parallel()
	if _, err := wire.ParseCPUInfo([]byte{0xD7}); !errors.Is(err, wire.ErrShortFrame) {
		t.Fatalf("1-byte buf: want ErrShortFrame, got %v", err)
	}
	if _, err := wire.ParseCPUInfo(nil); !errors.Is(err, wire.ErrShortFrame) {
		t.Fatalf("nil buf: want ErrShortFrame, got %v", err)
	}
	// Request marker (0x57) in a response position is not a response.
	if _, err := wire.ParseCPUInfo([]byte{0x57, 0x00, 0x00}); !errors.Is(err, wire.ErrNotResponse) {
		t.Fatalf("0x57 marker: want ErrNotResponse, got %v", err)
	}
	// 0xD7 but second byte not 0x00: not the 2-byte marker.
	if _, err := wire.ParseCPUInfo([]byte{0xD7, 0x99, 0x00}); !errors.Is(err, wire.ErrNotResponse) {
		t.Fatalf("0xD7 0x99: want ErrNotResponse, got %v", err)
	}
}

func TestIsResponseFrame(t *testing.T) {
	t.Parallel()
	if !wire.IsResponseFrame([]byte{0xD7, 0x00, 0x11}) {
		t.Fatal("expected true on a 0xD7 0x00 frame")
	}
	if wire.IsResponseFrame([]byte{0xD7}) {
		t.Fatal("1-byte buf should be false")
	}
	if wire.IsResponseFrame([]byte{0x57, 0x00}) {
		t.Fatal("request marker 0x57 must not be a response")
	}
	if wire.IsResponseFrame(nil) {
		t.Fatal("nil should be false")
	}
}

func TestRequestMatchesNSE(t *testing.T) {
	t.Parallel()
	// The exact getcpuinfopack from melsecq-discover.nse.
	want := []byte{
		0x57, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x07,
		0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x00, 0xfe,
		0x03, 0x00, 0x00, 0x14, 0x00, 0x1c, 0x08, 0x0a,
		0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	if !bytes.Equal(wire.BuildGetCPUInfo(), want) {
		t.Fatalf("request does not match the melsecq-discover.nse getcpuinfopack")
	}
}
