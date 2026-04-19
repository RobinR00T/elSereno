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
	if !strings.Contains(body, "critical: 1") || !strings.Contains(body, "medium: 1") {
		t.Fatalf("totals missing:\n%s", body)
	}
	if !strings.Contains(body, "modbus") || !strings.Contains(body, "s7") {
		t.Fatalf("protocols missing")
	}
	if !strings.Contains(body, "schema html:v1") {
		t.Fatalf("contract tag missing")
	}
}
