package modbus_test

import (
	"testing"

	"local/elsereno/internal/protocols/modbus"
	"local/elsereno/internal/protocols/modbus/wire"
)

func frame(unit uint8, pdu ...byte) wire.Frame {
	return wire.Frame{MBAP: wire.MBAP{Unit: unit, Length: uint16(1 + len(pdu))}, PDU: pdu} // #nosec G115 -- test-bounded
}

func kinds(evs []modbus.MonEvent) []modbus.MonEventKind {
	out := make([]modbus.MonEventKind, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func hasKind(evs []modbus.MonEvent, k modbus.MonEventKind) bool {
	for _, e := range evs {
		if e.Kind == k {
			return true
		}
	}
	return false
}

func TestMonitorReadIsSilent(t *testing.T) {
	m := modbus.NewMonitor()
	// FC 3 Read Holding Registers: addr 0, qty 10.
	evs := m.Observe(frame(1, 0x03, 0x00, 0x00, 0x00, 0x0A))
	if len(evs) != 0 {
		t.Fatalf("a read must be silent, got %v", kinds(evs))
	}
}

func TestMonitorWriteSingleRegister(t *testing.T) {
	m := modbus.NewMonitor()
	// FC 6 Write Single Register: addr 0x0010, value 0x00FF.
	evs := m.Observe(frame(2, 0x06, 0x00, 0x10, 0x00, 0xFF))
	if !hasKind(evs, modbus.EvWriteObserved) {
		t.Fatalf("expected write_observed, got %v", kinds(evs))
	}
	if evs[0].Severity != modbus.MonMedium || evs[0].Unit != 2 {
		t.Errorf("event = %+v", evs[0])
	}
}

func TestMonitorWriteMultipleCoils(t *testing.T) {
	m := modbus.NewMonitor()
	// FC 15 Write Multiple Coils: addr 0x0013, qty 10.
	evs := m.Observe(frame(1, 0x0F, 0x00, 0x13, 0x00, 0x0A, 0x02, 0xCD, 0x01))
	if !hasKind(evs, modbus.EvWriteObserved) {
		t.Fatalf("expected write_observed, got %v", kinds(evs))
	}
}

func TestMonitorDangerousDiagnostic(t *testing.T) {
	m := modbus.NewMonitor()
	// FC 8 sub 0x0001 Restart Communications (mutating).
	evs := m.Observe(frame(1, 0x08, 0x00, 0x01, 0xFF, 0x00))
	if !hasKind(evs, modbus.EvDangerousDiag) {
		t.Fatalf("expected dangerous_diagnostic, got %v", kinds(evs))
	}
	if evs[0].Severity != modbus.MonHigh {
		t.Errorf("dangerous diag must be high, got %s", evs[0].Severity)
	}
}

func TestMonitorReadOnlyDiagnosticIsSilent(t *testing.T) {
	m := modbus.NewMonitor()
	// FC 8 sub 0x0000 Return Query Data (loopback echo, read-only).
	evs := m.Observe(frame(1, 0x08, 0x00, 0x00, 0x12, 0x34))
	if len(evs) != 0 {
		t.Fatalf("a read-only diagnostic must be silent, got %v", kinds(evs))
	}
}

func TestMonitorException(t *testing.T) {
	m := modbus.NewMonitor()
	// Exception to FC 6 (0x86), code 0x02 Illegal Data Address.
	evs := m.Observe(frame(1, 0x86, 0x02))
	if !hasKind(evs, modbus.EvExceptionObserved) {
		t.Fatalf("expected exception_observed, got %v", kinds(evs))
	}
}
