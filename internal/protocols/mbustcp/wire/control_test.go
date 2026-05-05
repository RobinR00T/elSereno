package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// buildLongFrame constructs a long-frame on-wire payload with
// the supplied (control, address, ci, ud) tuple. Computes L and
// CS automatically. ud is 0..N user-data bytes appended after
// the CI byte.
func buildLongFrame(control, address, ci byte, ud []byte) []byte {
	bodyLen := 3 + len(ud) // C + A + CI + UD
	if bodyLen > 255 {
		panic("buildLongFrame: body too long for test fixture")
	}
	frame := make([]byte, 0, 4+bodyLen+2)
	// #nosec G115 -- bodyLen bound-checked above
	frame = append(frame, StartLong, byte(bodyLen), byte(bodyLen), StartLong)
	body := []byte{control, address, ci}
	body = append(body, ud...)
	var cs byte
	for _, b := range body {
		cs += b
	}
	frame = append(frame, body...)
	frame = append(frame, cs, StopByte)
	return frame
}

// TestReadFrame_ACK pins the single-byte ACK case.
func TestReadFrame_ACK(t *testing.T) {
	f, err := ReadFrame(bytes.NewReader([]byte{ACKByte}))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !f.IsACK {
		t.Errorf("IsACK = false")
	}
}

// TestReadFrame_Short pins a 5-byte short frame.
func TestReadFrame_Short(t *testing.T) {
	frame := []byte{StartShort, ControlREQUD2, 0x05, ControlREQUD2 + 0x05, StopByte}
	f, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !f.IsShort {
		t.Errorf("IsShort = false")
	}
	if f.Control != ControlREQUD2 {
		t.Errorf("Control = 0x%02x, want 0x%02x", f.Control, ControlREQUD2)
	}
	if f.Address != 0x05 {
		t.Errorf("Address = 0x%02x", f.Address)
	}
}

// TestReadFrame_LongSNDUD pins a long-frame SND_UD with CI =
// 0x51 (Data Send) to address 0x05.
func TestReadFrame_LongSNDUD(t *testing.T) {
	frame := buildLongFrame(ControlSNDUD, 0x05, CIDataSend, []byte{0xAA, 0xBB})
	f, err := ReadFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !f.IsLong {
		t.Errorf("IsLong = false")
	}
	if !f.IsSNDUD() {
		t.Errorf("IsSNDUD = false")
	}
	if f.CI != CIDataSend {
		t.Errorf("CI = 0x%02x, want 0x%02x", f.CI, CIDataSend)
	}
	if f.Address != 0x05 {
		t.Errorf("Address = 0x%02x", f.Address)
	}
	if !bytes.Equal(f.Raw, frame) {
		t.Errorf("Raw mismatch:\n got=%x\nwant=%x", f.Raw, frame)
	}
}

// TestReadFrame_UnknownStart refuses bytes that aren't 0x68 /
// 0x10 / 0xE5.
func TestReadFrame_UnknownStart(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0xAA}))
	if !errors.Is(err, ErrFrameUnknownStart) {
		t.Errorf("err = %v, want ErrFrameUnknownStart", err)
	}
}

// TestReadFrame_LongLengthMismatch refuses long frames whose
// L L bytes disagree.
func TestReadFrame_LongLengthMismatch(t *testing.T) {
	frame := []byte{StartLong, 0x05, 0x06, StartLong, 0x53, 0x05, 0x51, 0xA9, StopByte}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("err = %v, want ErrLengthMismatch", err)
	}
}

// TestReadFrame_LongMissingSecondStart refuses long frames whose
// 4th byte isn't 0x68.
func TestReadFrame_LongMissingSecondStart(t *testing.T) {
	frame := []byte{StartLong, 0x03, 0x03, 0x69, ControlSNDUD, 0x05, CIDataSend, ControlSNDUD + 0x05 + CIDataSend, StopByte}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrBadStart) {
		t.Errorf("err = %v, want ErrBadStart", err)
	}
}

// TestReadFrame_ShortChecksumMismatch refuses short frames with
// a wrong CS byte.
func TestReadFrame_ShortChecksumMismatch(t *testing.T) {
	frame := []byte{StartShort, ControlREQUD2, 0x05, 0x00, StopByte}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("err = %v, want ErrChecksumMismatch", err)
	}
}

// TestReadFrame_LongBadStop refuses long frames whose final
// byte isn't 0x16.
func TestReadFrame_LongBadStop(t *testing.T) {
	frame := buildLongFrame(ControlSNDUD, 0x05, CIDataSend, nil)
	frame[len(frame)-1] = 0x17
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrBadStop) {
		t.Errorf("err = %v, want ErrBadStop", err)
	}
}

// TestReadFrame_LongShortBody refuses long frames whose declared
// length is < 3 (need at least C + A + CI).
func TestReadFrame_LongShortBody(t *testing.T) {
	frame := []byte{StartLong, 0x02, 0x02, StartLong, 0x53, 0x05, 0x58, StopByte}
	_, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrShortFrame) {
		t.Errorf("err = %v, want ErrShortFrame", err)
	}
}

// TestReadFrame_TruncatedStream refuses partial reads. io.ReadFull
// returns io.EOF when ZERO bytes are read at the start of the
// expected chunk, and io.ErrUnexpectedEOF when a partial read
// dies mid-chunk. The gate treats both equivalently — connection
// is closed either way — so accept both.
func TestReadFrame_TruncatedStream(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"short-no-tail", []byte{StartShort, ControlREQUD2, 0x05}},
		{"long-no-body", []byte{StartLong, 0x05, 0x05, StartLong}},
		{"long-truncated-body", []byte{StartLong, 0x05, 0x05, StartLong, 0x53, 0x05, 0x51}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tc.data))
			if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
				t.Errorf("err = %v, want io.EOF or io.ErrUnexpectedEOF", err)
			}
		})
	}
}

// TestIsAlwaysSafeControl pins the canonical safe set.
func TestIsAlwaysSafeControl(t *testing.T) {
	for _, tc := range []struct {
		name    string
		frame   Frame
		expSafe bool
	}{
		{"sndnke", Frame{IsShort: true, Control: ControlSNDNKE}, true},
		{"requd1", Frame{IsShort: true, Control: ControlREQUD1}, true},
		{"requd2", Frame{IsShort: true, Control: ControlREQUD2}, true},
		{"requd2fcb", Frame{IsShort: true, Control: ControlREQUD2FCB}, true},
		{"sndud", Frame{IsLong: true, Control: ControlSNDUD}, false},
		{"sndudfcb", Frame{IsLong: true, Control: ControlSNDUDFCB}, false},
		{"ack-not-safe", Frame{IsACK: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.frame.IsAlwaysSafeControl()
			if got != tc.expSafe {
				t.Errorf("got %v, want %v", got, tc.expSafe)
			}
		})
	}
}
