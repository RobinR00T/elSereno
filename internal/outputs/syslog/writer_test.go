package syslog_test

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/syslog"
)

func sampleFinding() core.Finding {
	ts, _ := time.Parse(time.RFC3339, "2026-04-19T10:00:00Z")
	return core.Finding{
		ID:          "f-001",
		RunID:       "r-002",
		Protocol:    "modbus",
		Severity:    core.Severity("high"),
		Score:       75,
		FindingHash: []byte{0xde, 0xad, 0xbe, 0xef},
		CreatedAt:   ts,
		Factors:     map[string]int{"protocol_risk": 85, "exposure": 80},
	}
}

// priRE matches the opening <PRI> envelope.
var priRE = regexp.MustCompile(`^<(\d+)>1 `)

func TestWriter_HeaderShape(t *testing.T) {
	var buf bytes.Buffer
	w := syslog.NewWriter(&buf, "scan-host", "elsereno", "1.2.3")
	if err := w.WriteFinding(sampleFinding(), "10.0.0.1:502"); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	m := priRE.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("PRI not present: %q", line)
	}
	// Facility 17 * 8 + severity 3 (high) = 139.
	if m[1] != "139" {
		t.Fatalf("PRI = %q, want 139", m[1])
	}
	// Timestamp, hostname, app, procID "-", msgID "f-001" all expected.
	if !strings.Contains(line, " scan-host elsereno - f-001 [") {
		t.Fatalf("header fields wrong: %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("trailing newline missing")
	}
}

func TestWriter_StructuredDataSorted(t *testing.T) {
	var buf bytes.Buffer
	w := syslog.NewWriter(&buf, "h", "elsereno", "v1")
	_ = w.WriteFinding(sampleFinding(), "10.0.0.1:502")
	line := buf.String()
	start := strings.Index(line, "[elsereno@32473 ")
	end := strings.Index(line, "] ")
	if start < 0 || end < 0 || end < start {
		t.Fatalf("SD section missing: %q", line)
	}
	sd := line[start+len("[elsereno@32473 ") : end]
	// First key alphabetically should be "addr".
	if !strings.HasPrefix(sd, `addr="10.0.0.1:502"`) {
		t.Fatalf("sort failure: %q", sd)
	}
}

func TestWriter_SeverityMapping(t *testing.T) {
	cases := []struct {
		sev core.Severity
		pri int
	}{
		{"critical", 138},
		{"high", 139},
		{"medium", 140},
		{"low", 142},
		{"info", 143},
		{"weird", 141},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		w := syslog.NewWriter(&buf, "h", "a", "v")
		f := sampleFinding()
		f.Severity = c.sev
		_ = w.WriteFinding(f, "x")
		m := priRE.FindStringSubmatch(buf.String())
		if m == nil {
			t.Fatalf("no PRI")
		}
		if m[1] != fmt.Sprintf("%d", c.pri) {
			t.Errorf("sev %q: PRI=%s, want %d", c.sev, m[1], c.pri)
		}
	}
}

func TestWriter_FactorEmitted(t *testing.T) {
	var buf bytes.Buffer
	w := syslog.NewWriter(&buf, "h", "a", "v")
	_ = w.WriteFinding(sampleFinding(), "x")
	line := buf.String()
	if !strings.Contains(line, `factor_protocol_risk="85"`) {
		t.Fatalf("factor SD missing: %q", line)
	}
}

func TestWriter_EscapesSDSpecials(t *testing.T) {
	var buf bytes.Buffer
	w := syslog.NewWriter(&buf, "h", "a", "v")
	f := sampleFinding()
	f.Protocol = `proto"with]special`
	_ = w.WriteFinding(f, "x")
	line := buf.String()
	if !strings.Contains(line, `protocol="proto\"with\]special"`) {
		t.Fatalf("SD escapes missing: %q", line)
	}
}

func TestWriter_EmptyIDRejected(t *testing.T) {
	var buf bytes.Buffer
	w := syslog.NewWriter(&buf, "h", "a", "v")
	if err := w.WriteFinding(core.Finding{}, "x"); err == nil {
		t.Fatal("expected error on empty ID")
	}
}

func TestWriter_DefaultsFilled(t *testing.T) {
	var buf bytes.Buffer
	w := syslog.NewWriter(&buf, "", "", "")
	_ = w.WriteFinding(sampleFinding(), "x")
	line := buf.String()
	if !strings.Contains(line, " - elsereno -") {
		t.Fatalf("default hostname/app: %q", line)
	}
}
