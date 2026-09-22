//go:build offensive

package dnp3

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"local/elsereno/internal/protocols/dnp3/wire"
)

// respFrame builds an outstation response frame (control 0x44, FC 0x81)
// from the outstation (link 1) to the master (link 2) carrying the
// given IIN, with correct CRCs.
func respFrame(iin1, iin2 uint8) []byte {
	const dest, src uint16 = 2, 1
	userData := []byte{0xC0, 0xC0, 0x81, iin1, iin2}
	body := wire.AppendBlockCRCs(userData)
	f := make([]byte, wire.HeaderLen+len(body))
	f[0], f[1] = wire.StartBytes[0], wire.StartBytes[1]
	f[2] = uint8(5 + len(userData)) // #nosec G115 -- fixed 5-byte body
	f[3] = 0x44
	f[4], f[5] = byte(dest&0xFF), byte(dest>>8)
	f[6], f[7] = byte(src&0xFF), byte(src>>8)
	crc := wire.CRC16(f[0:8])
	f[8], f[9] = byte(crc&0xFF), byte(crc>>8)
	copy(f[wire.HeaderLen:], body)
	return f
}

// runResponses feeds `in` through forwardResponses and returns the
// captured events and the bytes written to the client.
func runResponses(t *testing.T, threshold int, in []byte) ([]IINEvent, []byte) {
	t.Helper()
	var events []IINEvent
	h := &WriteGatedHandler{
		IINErrorBurstThreshold: threshold,
		OnIIN:                  func(ev IINEvent) { events = append(events, ev) },
	}
	var client bytes.Buffer
	err := h.forwardResponses(bytes.NewReader(in), &client)
	// Normal end-of-stream is io.EOF (ReadFull at the frame boundary);
	// the framing-desync fallback drains via io.Copy and returns nil.
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("forwardResponses ended with %v, want clean EOF", err)
	}
	return events, client.Bytes()
}

// TestForwardResponses_Verbatim proves the response bytes pass through
// unchanged and a clean IIN raises no alert.
func TestForwardResponses_Verbatim(t *testing.T) {
	t.Parallel()
	in := respFrame(0, 0) // outstation 1 -> master 2, IIN clean
	events, out := runResponses(t, 0, in)
	if !bytes.Equal(out, in) {
		t.Fatal("response bytes were not forwarded verbatim")
	}
	if len(events) != 0 {
		t.Fatalf("clean IIN raised %d alert(s)", len(events))
	}
}

// TestForwardResponses_StateChange proves a Device Restart IIN raises a
// state-change alert while still forwarding the frame.
func TestForwardResponses_StateChange(t *testing.T) {
	t.Parallel()
	in := respFrame(wire.IIN1DeviceRestart, 0)
	events, out := runResponses(t, 0, in)
	if !bytes.Equal(out, in) {
		t.Fatal("frame not forwarded verbatim")
	}
	if len(events) != 1 || events[0].Kind != IINStateChangeKind {
		t.Fatalf("events = %+v, want one state_change", events)
	}
	if events[0].Src != 1 || events[0].Dest != 2 {
		t.Fatalf("event addresses = src %d dest %d, want src 1 dest 2", events[0].Src, events[0].Dest)
	}
	found := false
	for _, b := range events[0].Bits {
		if b == "device_restart" {
			found = true
		}
	}
	if !found {
		t.Fatalf("bits = %v, want device_restart", events[0].Bits)
	}
}

// TestForwardResponses_StateChangeDedup proves a run of identical
// state-change responses collapses to one alert, but the same
// condition re-alerts after an intervening clean response.
func TestForwardResponses_StateChangeDedup(t *testing.T) {
	t.Parallel()
	var in []byte
	// Three identical Device-Restart responses in a row.
	for i := 0; i < 3; i++ {
		in = append(in, respFrame(wire.IIN1DeviceRestart, 0)...)
	}
	// A clean response, then Device Restart again.
	in = append(in, respFrame(0, 0)...)
	in = append(in, respFrame(wire.IIN1DeviceRestart, 0)...)
	events, _ := runResponses(t, 0, in)
	state := 0
	for _, e := range events {
		if e.Kind == IINStateChangeKind {
			state++
		}
	}
	if state != 2 {
		t.Fatalf("state_change alerts = %d, want 2 (run collapsed, then re-alert)", state)
	}
}

// TestForwardResponses_ErrorBurst proves a run of error responses trips
// exactly one enumeration/fuzzing alert at the threshold.
func TestForwardResponses_ErrorBurst(t *testing.T) {
	t.Parallel()
	var in []byte
	for i := 0; i < 5; i++ {
		in = append(in, respFrame(0, wire.IIN2FuncNotSupp)...)
	}
	events, _ := runResponses(t, 3, in)
	burst := 0
	for _, e := range events {
		if e.Kind == IINErrorBurstKind {
			burst++
			if e.ErrorRun < 3 {
				t.Errorf("burst fired at run %d, want >= 3", e.ErrorRun)
			}
		}
	}
	if burst != 1 {
		t.Fatalf("error_burst fired %d times, want exactly 1", burst)
	}
}

// TestForwardResponses_FramingDesyncFailsOpen proves that if the stream
// is not DNP3-framed, the bytes are still delivered (observation must
// never corrupt the master's stream).
func TestForwardResponses_FramingDesyncFailsOpen(t *testing.T) {
	t.Parallel()
	in := []byte{0x05, 0x64, 0x02, 0x99, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0xAA, 0xBB}
	// Length 2 < 5 makes ParseHeader fail; the forwarder must still
	// deliver every byte.
	_, out := runResponses(t, 0, in)
	if !bytes.Equal(out, in) {
		t.Fatalf("desync dropped bytes: got % x want % x", out, in)
	}
}
