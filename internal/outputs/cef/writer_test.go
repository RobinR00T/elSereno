package cef_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/cef"
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

func TestWriter_HeaderShape(t *testing.T) {
	var buf bytes.Buffer
	w := cef.NewWriter(&buf, "1.2.3")
	if err := w.WriteFinding(sampleFinding(), "10.0.0.1:502"); err != nil {
		t.Fatal(err)
	}
	line := buf.String()
	if !strings.HasPrefix(line, "CEF:0|ElSereno|elsereno|1.2.3|modbus|modbus probe|7|") {
		t.Fatalf("header = %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("trailing newline missing")
	}
}

func TestWriter_ExtensionsSorted(t *testing.T) {
	var buf bytes.Buffer
	w := cef.NewWriter(&buf, "1.0")
	_ = w.WriteFinding(sampleFinding(), "10.0.0.1:502")
	line := buf.String()
	// Extract extension portion (after the 8th pipe).
	parts := strings.SplitN(line, "|", 8)
	ext := strings.TrimRight(parts[7], "\n")
	// First key should be alphabetically first (`cat`).
	if !strings.HasPrefix(ext, "cat=") {
		t.Fatalf("sort failure, first key: %q", ext[:40])
	}
	// Severity mapping: score 75 -> CEF 7 (75/10=7).
	if !strings.Contains(line, "modbus probe|7|") {
		t.Fatalf("expected CEF severity 7, line: %q", line)
	}
}

func TestWriter_ExternalIDAndScore(t *testing.T) {
	var buf bytes.Buffer
	w := cef.NewWriter(&buf, "v1")
	_ = w.WriteFinding(sampleFinding(), "10.0.0.1:502")
	line := buf.String()
	if !strings.Contains(line, "externalId=f-001") {
		t.Fatalf("externalId missing: %s", line)
	}
	if !strings.Contains(line, "cn1=75") {
		t.Fatalf("score cn1 missing: %s", line)
	}
	if !strings.Contains(line, "elseFactor_protocol_risk=85") {
		t.Fatalf("factor missing: %s", line)
	}
}

func TestWriter_EscapesPipeInName(t *testing.T) {
	var buf bytes.Buffer
	w := cef.NewWriter(&buf, "vendor|with|pipes")
	_ = w.WriteFinding(sampleFinding(), "10.0.0.1:502")
	line := buf.String()
	// Version should have pipes escaped.
	if !strings.Contains(line, `vendor\|with\|pipes`) {
		t.Fatalf("pipes not escaped: %s", line)
	}
}

func TestWriter_EscapesEqualsInExtension(t *testing.T) {
	var buf bytes.Buffer
	w := cef.NewWriter(&buf, "v")
	f := sampleFinding()
	f.Protocol = "proto=with=equals"
	_ = w.WriteFinding(f, "10.0.0.1:502")
	line := buf.String()
	if !strings.Contains(line, `cs1=proto\=with\=equals`) {
		t.Fatalf("equals not escaped in value: %s", line)
	}
}

func TestWriter_EmptyIDRejected(t *testing.T) {
	var buf bytes.Buffer
	w := cef.NewWriter(&buf, "v")
	err := w.WriteFinding(core.Finding{}, "x")
	if err == nil {
		t.Fatal("expected error on empty ID")
	}
}

func TestWriter_SeverityMapping(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "|1|"},
		{9, "|1|"},
		{10, "|1|"},
		{50, "|5|"},
		{100, "|10|"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		w := cef.NewWriter(&buf, "v")
		f := sampleFinding()
		f.Score = c.score
		_ = w.WriteFinding(f, "x")
		if !strings.Contains(buf.String(), c.want) {
			t.Errorf("score=%d: want %q, got %s", c.score, c.want, buf.String())
		}
	}
}
