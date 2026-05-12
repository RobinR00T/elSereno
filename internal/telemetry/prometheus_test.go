package telemetry_test

import (
	"testing"

	"local/elsereno/internal/telemetry"
)

func TestSanitiseLabels(t *testing.T) {
	t.Parallel()
	cases := []struct {
		protocol, severity, asn, country string
		wantP, wantS, wantA, wantC       string
	}{
		{"modbus", "critical", "12345", "ES", "modbus", "critical", "12345", "ES"},
		{"MODBUS", "critical", "12345", "ES", telemetry.LabelUnknown, "critical", "12345", "ES"},
		{"modbus", "wat", "abc", "esp", "modbus", telemetry.LabelUnknown, telemetry.LabelUnknown, telemetry.LabelUnknown},
		{"", "", "", "", telemetry.LabelUnknown, telemetry.LabelUnknown, telemetry.LabelUnknown, telemetry.LabelUnknown},
		{"quic", "high", "-1", "US", telemetry.LabelUnknown, "high", telemetry.LabelUnknown, "US"},
	}
	for _, c := range cases {
		p, s, a, ctry := telemetry.SanitiseLabels(c.protocol, c.severity, c.asn, c.country)
		if p != c.wantP || s != c.wantS || a != c.wantA || ctry != c.wantC {
			t.Fatalf("SanitiseLabels(%q,%q,%q,%q) = (%q,%q,%q,%q); want (%q,%q,%q,%q)",
				c.protocol, c.severity, c.asn, c.country,
				p, s, a, ctry,
				c.wantP, c.wantS, c.wantA, c.wantC)
		}
	}
}

func TestMetricsHandlerSmoke(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics(nil)
	m.FindingsTotal.WithLabelValues("modbus", "high", "12345", "ES").Inc()
	m.AuditEntriesTotal.Inc()
	m.OutboxInflight.Set(3)
	m.PersistenceLagSec.Set(0.25)
	if m.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

// TestAuditPrunerMetricsRegistered (v1.91+): the v1.91 pruner
// counters must be registered + writable. Tests the labelled
// counter's 3 expected results + the events-deleted total.
func TestAuditPrunerMetricsRegistered(t *testing.T) {
	t.Parallel()
	m := telemetry.NewMetrics(nil)
	// Each label value must be acceptable to the counter.
	for _, result := range []string{"acquired", "skipped_lock", "error"} {
		c := m.AuditPrunerRunsTotal.WithLabelValues(result)
		if c == nil {
			t.Fatalf("AuditPrunerRunsTotal[%q] = nil", result)
		}
		c.Inc()
	}
	m.AuditPrunerEventsDeletedTotal.Add(100)
	// Smoke: the handler renders all instruments without
	// panicking.
	if m.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}
