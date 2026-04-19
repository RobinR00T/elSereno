package html

import (
	"fmt"
	"html/template"
	"io"
	"time"

	"local/elsereno/internal/core"
)

// Contract is the schema identifier for the HTML v1 output.
const Contract = "html:v1"

// Report is the data model passed to the template.
type Report struct {
	Title       string
	GeneratedAt string
	Findings    []core.Finding
	Totals      TotalsByBucket
}

// TotalsByBucket is the summary used in the top of the report.
type TotalsByBucket struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// Render writes a self-contained HTML report to w.
func Render(w io.Writer, r Report) error {
	if r.Title == "" {
		r.Title = "ElSereno report"
	}
	if r.GeneratedAt == "" {
		r.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	t, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("html: parse template: %w", err)
	}
	if err := t.Execute(w, r); err != nil {
		return fmt.Errorf("html: render: %w", err)
	}
	return nil
}

// Tally computes the TotalsByBucket from a slice of findings.
func Tally(findings []core.Finding) TotalsByBucket {
	var t TotalsByBucket
	for _, f := range findings {
		switch f.Severity {
		case core.SeverityCritical:
			t.Critical++
		case core.SeverityHigh:
			t.High++
		case core.SeverityMedium:
			t.Medium++
		case core.SeverityLow:
			t.Low++
		default:
			t.Info++
		}
	}
	return t
}

// reportTemplate is kept inline for the F1 chunk 2 scaffold. A richer
// embed.FS template tree lands alongside the web dashboard in chunk 3.
const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; color: #111; }
  h1 { margin-top: 0; }
  .totals { display: flex; gap: 1rem; margin-bottom: 2rem; }
  .totals div { padding: .5rem 1rem; border: 1px solid #ddd; border-radius: 4px; }
  .critical { background: #fee; }
  .high     { background: #fec; }
  .medium   { background: #ffd; }
  .low      { background: #efd; }
  .info     { background: #eef; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; }
  th { background: #f4f4f4; }
  code { font-family: "JetBrains Mono", "Menlo", monospace; }
</style>
</head>
<body>
<h1>{{.Title}}</h1>
<p><em>Generated {{.GeneratedAt}} · schema html:v1</em></p>

<div class="totals">
  <div class="critical">critical: {{.Totals.Critical}}</div>
  <div class="high">high: {{.Totals.High}}</div>
  <div class="medium">medium: {{.Totals.Medium}}</div>
  <div class="low">low: {{.Totals.Low}}</div>
  <div class="info">info: {{.Totals.Info}}</div>
</div>

<table>
  <thead>
    <tr><th>Score</th><th>Severity</th><th>Protocol</th><th>Finding ID</th><th>Target</th></tr>
  </thead>
  <tbody>
  {{- range .Findings }}
    <tr>
      <td>{{.Score}}</td>
      <td>{{.Severity}}</td>
      <td>{{.Protocol}}</td>
      <td><code>{{.ID}}</code></td>
      <td><code>{{.TargetID}}</code></td>
    </tr>
  {{- end }}
  </tbody>
</table>
</body>
</html>
`
