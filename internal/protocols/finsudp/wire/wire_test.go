package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/finsudp/wire"
)

func TestBuildControllerDataReadFrameLayout(t *testing.T) {
	t.Parallel()
	got := wire.BuildControllerDataRead(0x42)
	want := []byte{
		0x80, 0x00, 0x02, // ICF / RSV / GCT
		0x00, 0x00, 0x00, // DNA / DA1 / DA2
		0x00, 0x01, 0x00, // SNA / SA1 / SA2
		0x42,             // SID echoes caller value
		0x05, 0x01, 0x00, // MRC / SRC / area=0
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("frame mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestBuildControllerDataReadSIDIsParameter(t *testing.T) {
	t.Parallel()
	for _, sid := range []byte{0x00, 0x01, 0x7F, 0xFF} {
		got := wire.BuildControllerDataRead(sid)
		if got[9] != sid {
			t.Fatalf("SID byte: got 0x%02x want 0x%02x", got[9], sid)
		}
	}
}

func TestParseControllerDataReadFullFrame(t *testing.T) {
	t.Parallel()
	frame := buildResp(0x11, "CJ2M-CPU33          ", "V1.04 OMRON CO.     ", "1.04 SYS            ")
	cd, err := wire.ParseControllerDataRead(frame, 0x11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cd.Model != "CJ2M-CPU33" {
		t.Fatalf("Model: got %q", cd.Model)
	}
	if cd.InternalCode != "V1.04 OMRON CO." {
		t.Fatalf("InternalCode: got %q", cd.InternalCode)
	}
	if cd.SystemVersion != "1.04 SYS" {
		t.Fatalf("SystemVersion: got %q", cd.SystemVersion)
	}
}

func TestParseControllerDataReadTruncatedAccepted(t *testing.T) {
	t.Parallel()
	// Older CPUs return only Model + InternalCode (54 bytes total).
	frame := buildRespNoSysVer(0x22, "NJ501-1500          ", "V1.10               ")
	cd, err := wire.ParseControllerDataRead(frame, 0x22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cd.Model != "NJ501-1500" {
		t.Fatalf("Model: got %q", cd.Model)
	}
	if cd.InternalCode != "V1.10" {
		t.Fatalf("InternalCode: got %q", cd.InternalCode)
	}
	if cd.SystemVersion != "" {
		t.Fatalf("SystemVersion should be empty: got %q", cd.SystemVersion)
	}
}

func TestParseControllerDataReadShortFrameRejected(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 9, 13} {
		_, err := wire.ParseControllerDataRead(make([]byte, n), 0x00)
		if !errors.Is(err, wire.ErrShortFrame) {
			t.Fatalf("len=%d: expected ErrShortFrame, got %v", n, err)
		}
	}
}

func TestParseControllerDataReadRejectsRequestICF(t *testing.T) {
	t.Parallel()
	frame := buildResp(0x33, "                    ", "                    ", "                    ")
	frame[0] = 0x80 // request ICF — bit 6 cleared
	_, err := wire.ParseControllerDataRead(frame, 0x33)
	if !errors.Is(err, wire.ErrNotResponse) {
		t.Fatalf("expected ErrNotResponse, got %v", err)
	}
}

func TestParseControllerDataReadRejectsSIDMismatch(t *testing.T) {
	t.Parallel()
	frame := buildResp(0x44, "                    ", "                    ", "                    ")
	_, err := wire.ParseControllerDataRead(frame, 0x99)
	if !errors.Is(err, wire.ErrServiceMismatch) {
		t.Fatalf("expected ErrServiceMismatch, got %v", err)
	}
}

func TestParseControllerDataReadRejectsWrongMRCSRC(t *testing.T) {
	t.Parallel()
	frame := buildResp(0x55, "                    ", "                    ", "                    ")
	// Twiddle MRC to a non-controller-data value.
	frame[10] = 0x01
	_, err := wire.ParseControllerDataRead(frame, 0x55)
	if !errors.Is(err, wire.ErrNotResponse) {
		t.Fatalf("expected ErrNotResponse on wrong MRC, got %v", err)
	}
}

func TestParseControllerDataReadRejectsNonZeroEndCode(t *testing.T) {
	t.Parallel()
	frame := buildResp(0x66, "                    ", "                    ", "                    ")
	frame[12] = 0x01 // upper end-code byte non-zero
	_, err := wire.ParseControllerDataRead(frame, 0x66)
	if !errors.Is(err, wire.ErrEndCodeNonZero) {
		t.Fatalf("expected ErrEndCodeNonZero, got %v", err)
	}
}

func TestParseControllerDataReadTrimsNULsAndSpaces(t *testing.T) {
	t.Parallel()
	model := []byte("CP1L-EM30      \x00\x00\x00\x00\x00")
	frame := append(buildHeader(0x77), 0x00, 0x00) // end code
	frame = append(frame, model...)
	cd, err := wire.ParseControllerDataRead(frame, 0x77)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cd.Model != "CP1L-EM30" {
		t.Fatalf("Model trim: got %q", cd.Model)
	}
}

func TestIsResponseTrueOnly(t *testing.T) {
	t.Parallel()
	resp := buildResp(0x88, "                    ", "                    ", "                    ")
	if !wire.IsResponse(resp) {
		t.Fatalf("expected IsResponse true on a complete response frame")
	}
	req := wire.BuildControllerDataRead(0x00)
	if wire.IsResponse(req) {
		t.Fatalf("expected IsResponse false on a request frame")
	}
	if wire.IsResponse(nil) {
		t.Fatalf("nil should not be a response")
	}
	if wire.IsResponse([]byte{0xC0}) {
		t.Fatalf("single response-bit byte too short to be a response")
	}
}

// buildHeader produces a 12-byte "response header" prefix (10 header
// + MRC + SRC) with the response bit set and the supplied SID.
func buildHeader(sid byte) []byte {
	return []byte{
		0xC0, 0x00, 0x02, // ICF / RSV / GCT — response bit set
		0x00, 0x01, 0x00, // DNA / DA1 / DA2
		0x00, 0x00, 0x00, // SNA / SA1 / SA2
		sid,
		0x05, 0x01, // MRC / SRC
	}
}

// buildResp returns a full 74-byte response with the three 20-byte
// fields populated. Each field must be exactly 20 bytes.
func buildResp(sid byte, model, internal, sys string) []byte {
	if len(model) != 20 || len(internal) != 20 || len(sys) != 20 {
		panic("buildResp: each field must be exactly 20 bytes")
	}
	frame := append(buildHeader(sid), 0x00, 0x00) // end code
	frame = append(frame, []byte(model)...)
	frame = append(frame, []byte(internal)...)
	frame = append(frame, []byte(sys)...)
	return frame
}

// buildRespNoSysVer returns a 54-byte response (header + end code +
// model + internal code only). Older CPUs.
func buildRespNoSysVer(sid byte, model, internal string) []byte {
	if len(model) != 20 || len(internal) != 20 {
		panic("buildRespNoSysVer: each field must be exactly 20 bytes")
	}
	frame := append(buildHeader(sid), 0x00, 0x00) // end code
	frame = append(frame, []byte(model)...)
	frame = append(frame, []byte(internal)...)
	return frame
}
