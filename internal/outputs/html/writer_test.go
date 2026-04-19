package html_test

import (
	"bytes"
	"strings"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/html"
)

func TestRenderSmoke(t *testing.T) {
	t.Parallel()
	findings := []core.Finding{
		{ID: "f1", Protocol: "modbus", Severity: core.SeverityCritical, Score: 95, TargetID: "t1"},
		{ID: "f2", Protocol: "s7", Severity: core.SeverityMedium, Score: 45, TargetID: "t2"},
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, html.Report{
		Title:    "t",
		Findings: findings,
		Totals:   html.Tally(findings),
	}); err != nil {
		t.Fatalf("Render: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "<title>t</title>") {
		t.Fatalf("title missing")
	}
	// Polished template shows numeric cards rather than "critical: 1"
	// prose. Verify one critical + one medium + severity labels.
	if !strings.Contains(body, `"num">1</div><div class="lbl">Critical`) ||
		!strings.Contains(body, `"num">1</div><div class="lbl">Medium`) {
		t.Fatalf("totals missing:\n%s", body)
	}
	if !strings.Contains(body, "modbus") || !strings.Contains(body, "s7") {
		t.Fatalf("protocols missing")
	}
	if !strings.Contains(body, "schema html:v1") {
		t.Fatalf("contract tag missing")
	}
}

func TestTallyByProtocol(t *testing.T) {
	findings := []core.Finding{
		{ID: "a", Protocol: "modbus", Score: 80},
		{ID: "b", Protocol: "modbus", Score: 60},
		{ID: "c", Protocol: "s7", Score: 90},
	}
	var buf bytes.Buffer
	_ = html.Render(&buf, html.Report{Title: "t", Findings: findings, Totals: html.Tally(findings)})
	body := buf.String()
	// Per-protocol section shows "modbus · 2 findings · max 80 · avg 70".
	if !strings.Contains(body, "modbus · 2 findings · max 80 · avg 70") {
		t.Fatalf("modbus section missing: %q", body)
	}
	if !strings.Contains(body, "s7 · 1 findings · max 90 · avg 90") {
		t.Fatalf("s7 section missing: %q", body)
	}
}

func TestTopFactorsHistogram(t *testing.T) {
	findings := []core.Finding{
		{ID: "a", Protocol: "m", Score: 80, Factors: map[string]int{"protocol_risk": 90, "exposure": 80}},
		{ID: "b", Protocol: "m", Score: 60, Factors: map[string]int{"protocol_risk": 70, "exposure": 60}},
	}
	var buf bytes.Buffer
	_ = html.Render(&buf, html.Report{Title: "t", Findings: findings, Totals: html.Tally(findings)})
	body := buf.String()
	// protocol_risk average = (90+70)/2 = 80; exposure = 70.
	if !strings.Contains(body, "protocol_risk") || !strings.Contains(body, "width: 80%") {
		t.Fatalf("protocol_risk histogram missing: %q", body)
	}
}

func TestRenderEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := html.Render(&buf, html.Report{Findings: nil, Totals: html.Tally(nil)}); err != nil {
		t.Fatalf("empty render: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "ElSereno report") {
		t.Fatalf("default title missing")
	}
	if !strings.Contains(body, `"num">0</div>`) {
		t.Fatalf("zero counts missing")
	}
}
