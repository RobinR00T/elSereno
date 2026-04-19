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
