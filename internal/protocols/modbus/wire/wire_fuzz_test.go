package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/modbus/wire"
)

// FuzzParseMBAP asserts that ParseMBAP never panics and that, on
// success, Protocol == 0 and Length is in the legal range.
func FuzzParseMBAP(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01})
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := wire.ParseMBAP(b)
		if err != nil {
			return
		}
		if m.Protocol != wire.ProtocolID {
			t.Fatalf("Protocol=%d", m.Protocol)
		}
		if m.Length < 2 || int(m.Length) > wire.MaxPDULen+1 {
			t.Fatalf("Length=%d out of range", m.Length)
		}
	})
}

// FuzzReadFrameRoundTrip asserts WriteFrame + ReadFrame round-trip
// any PDU within the legal range.
func FuzzReadFrameRoundTrip(f *testing.F) {
	f.Add(uint16(1), uint8(1), []byte{0x01, 0x00, 0x00, 0x00, 0x01})
	f.Add(uint16(0xFFFF), uint8(0xFF), []byte{0x03, 0x00, 0x10, 0x00, 0x02})
	f.Fuzz(func(t *testing.T, tx uint16, unit uint8, pdu []byte) {
		if len(pdu) < 1 || len(pdu) > wire.MaxPDULen {
			return
		}
		frame := wire.Frame{
			MBAP: wire.MBAP{TxID: tx, Unit: unit},
			PDU:  pdu,
		}
		var buf bytes.Buffer
		if err := wire.WriteFrame(&buf, frame); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
		got, err := wire.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if got.MBAP.TxID != tx || got.MBAP.Unit != unit {
			t.Fatalf("MBAP mismatch")
		}
		if !bytes.Equal(got.PDU, pdu) {
			t.Fatalf("PDU mismatch")
		}
	})
}

// FuzzDeviceIDObjects asserts that DeviceIDObjects never panics on
// adversarial MEI responses.
func FuzzDeviceIDObjects(f *testing.F) {
	f.Add([]byte{0x2B, 0x0E, 0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{0x2B, 0x0E, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 'A', 'B'})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.DeviceIDObjects(b)
	})
}
