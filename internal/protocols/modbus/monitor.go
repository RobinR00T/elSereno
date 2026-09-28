package modbus

import (
	"encoding/binary"
	"fmt"

	"local/elsereno/internal/protocols/modbus/wire"
)

// Passive Modbus/TCP monitor. Modbus has no authentication or integrity
// on the wire, so any write or state-changing diagnostic observed on a
// link is a reportable exposure event: whoever put it there did not have
// to prove who they were. This is the passive counterpart to the
// offensive write-gate (which sits inline and blocks); the monitor sits
// on a tap / SPAN port / capture and reports what crossed the line.
//
// It complements the GOOSE/SV monitor (internal/protocols/goose): same
// "watch the line, flag the mutations" shape, different protocol.

// MonSeverity ranks a MonEvent.
type MonSeverity string

// MonSeverity levels.
const (
	MonInfo   MonSeverity = "info"
	MonLow    MonSeverity = "low"
	MonMedium MonSeverity = "medium"
	MonHigh   MonSeverity = "high"
)

// MonEventKind names a detected condition.
type MonEventKind string

// MonEvent kinds.
const (
	// EvWriteObserved: a state-changing function code crossed the wire.
	EvWriteObserved MonEventKind = "write_observed"
	// EvDangerousDiag: an FC 8 Diagnostics request with a mutating
	// sub-function (restart, force-listen-only DoS, clear counters).
	EvDangerousDiag MonEventKind = "dangerous_diagnostic"
	// EvExceptionObserved: a Modbus exception response (device rejected a
	// request); useful as a probe/scan or misconfiguration tell.
	EvExceptionObserved MonEventKind = "exception_observed"
)

// MonEvent is one notable Modbus observation.
type MonEvent struct {
	Kind     MonEventKind
	Severity MonSeverity
	Unit     uint8
	FC       wire.FunctionCode
	Detail   string
}

// String renders a MonEvent for the CLI.
func (e MonEvent) String() string {
	return fmt.Sprintf("[%s] %s unit=%d fc=0x%02x %s", e.Severity, e.Kind, e.Unit, byte(e.FC), e.Detail)
}

// Monitor is a passive Modbus/TCP observer. It is stateless per frame:
// every write is independently notable because Modbus authenticates
// nothing.
type Monitor struct{}

// NewMonitor returns a Monitor.
func NewMonitor() *Monitor { return &Monitor{} }

// Observe classifies one Modbus/TCP frame (MBAP + PDU) and returns any
// notable events. Reads produce no event.
func (m *Monitor) Observe(f wire.Frame) []MonEvent {
	unit := f.MBAP.Unit
	fc := f.FunctionCode()

	if f.IsExceptionFrame() {
		detail := "exception response"
		if code, ok := f.ExceptionCode(); ok {
			detail = fmt.Sprintf("exception response, code 0x%02x", byte(code))
		}
		return []MonEvent{{Kind: EvExceptionObserved, Severity: MonLow, Unit: unit, FC: fc, Detail: detail}}
	}

	switch wire.Classify(fc) {
	case wire.CategoryWrite:
		return []MonEvent{{Kind: EvWriteObserved, Severity: MonMedium, Unit: unit, FC: fc, Detail: describeWrite(f)}}
	case wire.CategoryDiagnostic:
		if sub, ok := f.DiagSubFunction(); ok && !wire.DiagIsReadOnly(sub) {
			return []MonEvent{{
				Kind: EvDangerousDiag, Severity: MonHigh, Unit: unit, FC: fc,
				Detail: fmt.Sprintf("mutating diagnostic sub-function 0x%04x", uint16(sub)),
			}}
		}
	case wire.CategoryUnknown, wire.CategoryRead, wire.CategoryMEI:
		// Reads, MEI (device-id) and unknown FCs are not reported here.
	}
	return nil
}

// describeWrite decodes the target of a write for a friendlier detail
// string. Single writes carry (address, value); multiple writes carry
// (address, quantity). Falls back to the FC alone when the PDU is short.
func describeWrite(f wire.Frame) string {
	pdu := f.PDU
	fc := f.FunctionCode()
	switch fc { //nolint:exhaustive // only single/multiple writes get a decoded target; other writes fall back to the FC alone
	case wire.FCWriteSingleCoil, wire.FCWriteSingleRegister:
		if len(pdu) >= 5 {
			addr := binary.BigEndian.Uint16(pdu[1:3])
			val := binary.BigEndian.Uint16(pdu[3:5])
			return fmt.Sprintf("write fc=0x%02x addr=%d value=0x%04x", byte(fc), addr, val)
		}
	case wire.FCWriteMultipleCoils, wire.FCWriteMultipleRegisters:
		if len(pdu) >= 5 {
			addr := binary.BigEndian.Uint16(pdu[1:3])
			qty := binary.BigEndian.Uint16(pdu[3:5])
			return fmt.Sprintf("write fc=0x%02x addr=%d qty=%d", byte(fc), addr, qty)
		}
	}
	return fmt.Sprintf("write fc=0x%02x", byte(fc))
}
