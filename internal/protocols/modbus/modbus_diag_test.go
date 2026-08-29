package modbus

import (
	"encoding/binary"
	"testing"

	"local/elsereno/internal/protocols/modbus/wire"
)

// FC 8 (Diagnostics) straddles read/write: the default write-ban must
// let the pure-read sub-functions through and block the state-changing
// ones (Restart 0x01, Change Delimiter 0x03, Force Listen Only 0x04,
// Clear Counters 0x0A), which are the DoS vectors on the PLC.
func TestDiagnosticsGating(t *testing.T) {
	fc8 := func(sub uint16) wire.Frame {
		pdu := []byte{byte(wire.FCDiagnostics), 0, 0}
		binary.BigEndian.PutUint16(pdu[1:3], sub)
		return wire.Frame{MBAP: wire.MBAP{TxID: 1, Unit: 1}, PDU: pdu}
	}

	for _, sub := range []uint16{0x0000, 0x0002, 0x000B, 0x0012} {
		if shouldBlock(fc8(sub)) {
			t.Errorf("FC8 sub 0x%04x: blocked, want allowed (read-only)", sub)
		}
	}
	for _, sub := range []uint16{0x0001, 0x0003, 0x0004, 0x000A} {
		if !shouldBlock(fc8(sub)) {
			t.Errorf("FC8 sub 0x%04x: allowed, want blocked (mutates state)", sub)
		}
	}
	trunc := wire.Frame{MBAP: wire.MBAP{Unit: 1}, PDU: []byte{byte(wire.FCDiagnostics)}}
	if !shouldBlock(trunc) {
		t.Error("truncated FC8 allowed, want blocked")
	}
}
