package html

import (
	"fmt"
	"html/template"
	"io"
	"sort"
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
	ByProtocol  []ProtocolBucket
	TopFactors  []FactorBar
	MaxFactor   int
	Count       int
}

// TotalsByBucket is the summary used in the top of the report.
type TotalsByBucket struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// ProtocolBucket aggregates findings per protocol for the per-
// protocol section of the report.
type ProtocolBucket struct {
	Protocol string
	Count    int
	AvgScore int
	MaxScore int
	Findings []core.Finding
}

// FactorBar is one row of the aggregate-factor histogram.
type FactorBar struct {
	Name    string
	Average int
}

// Render writes a self-contained HTML report to w.
func Render(w io.Writer, r Report) error {
	if r.Title == "" {
		r.Title = "ElSereno report"
	}
	if r.GeneratedAt == "" {
		r.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	r.Count = len(r.Findings)
	r.ByProtocol = tallyByProtocol(r.Findings)
	r.TopFactors = tallyTopFactors(r.Findings)
	r.MaxFactor = 100
	t, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("html: parse template: %w", err)
	}
	if err := t.Execute(w, r); err != nil {
		return fmt.Errorf("html: render: %w", err)
	}
	return nil
}

// tallyByProtocol groups findings by Protocol and computes per-group
// counts + average + max score. Output is sorted by Protocol for
// diffable reports.
func tallyByProtocol(findings []core.Finding) []ProtocolBucket {
	by := map[string]*ProtocolBucket{}
	for _, f := range findings {
		b, ok := by[f.Protocol]
		if !ok {
			b = &ProtocolBucket{Protocol: f.Protocol}
			by[f.Protocol] = b
		}
		b.Count++
		b.Findings = append(b.Findings, f)
		if f.Score > b.MaxScore {
			b.MaxScore = f.Score
		}
	}
	out := make([]ProtocolBucket, 0, len(by))
	for _, b := range by {
		sum := 0
		for _, f := range b.Findings {
			sum += f.Score
		}
		if b.Count > 0 {
			b.AvgScore = sum / b.Count
		}
		// Sort findings within a protocol by descending score so the
		// worst offenders surface at the top.
		sort.Slice(b.Findings, func(i, j int) bool { return b.Findings[i].Score > b.Findings[j].Score })
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Protocol < out[j].Protocol })
	return out
}

// tallyTopFactors computes the average of every factor across all
// findings; the top five (by average) drive the histogram.
func tallyTopFactors(findings []core.Finding) []FactorBar {
	sums := map[string]int{}
	counts := map[string]int{}
	for _, f := range findings {
		for k, v := range f.Factors {
			sums[k] += v
			counts[k]++
		}
	}
	bars := make([]FactorBar, 0, len(sums))
	for k, s := range sums {
		c := counts[k]
		if c == 0 {
			continue
		}
		bars = append(bars, FactorBar{Name: k, Average: s / c})
	}
	sort.Slice(bars, func(i, j int) bool {
		if bars[i].Average != bars[j].Average {
			return bars[i].Average > bars[j].Average
		}
		return bars[i].Name < bars[j].Name
	})
	if len(bars) > 5 {
		bars = bars[:5]
	}
	return bars
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

// reportTemplate is the self-contained HTML report. Single-file
// design: embedded CSS, no external fetches, safe for offline
// operators. Supports light and prefers-color-scheme: dark.
const reportTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
  :root {
    --bg: #f7f8fa;
    --panel: #ffffff;
    --ink: #111418;
    --muted: #6b7280;
    --border: #e5e7eb;
    --accent: #0f62fe;
    --critical: #dc2626;
    --high:     #ea580c;
    --medium:   #d97706;
    --low:      #059669;
    --info:     #0284c7;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0d10;
      --panel: #13161a;
      --ink: #e5e7eb;
      --muted: #9ca3af;
      --border: #2a2f37;
      --accent: #3b82f6;
    }
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    padding: 2rem;
    background: var(--bg);
    color: var(--ink);
    line-height: 1.5;
  }
  header { margin-bottom: 2rem; }
  h1 { margin: 0 0 .25rem 0; font-size: 1.75rem; letter-spacing: -0.02em; }
  .meta { color: var(--muted); font-size: .9rem; }
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
  }
  .panel h2 { margin: 0 0 .75rem 0; font-size: 1.1rem; }
  .totals {
    display: grid;
    grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: .75rem;
  }
  .totals .card {
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    text-align: center;
  }
  .totals .num { font-size: 1.75rem; font-weight: 600; }
  .totals .lbl { font-size: .8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .card.critical { border-left: 4px solid var(--critical); }
  .card.high     { border-left: 4px solid var(--high); }
  .card.medium   { border-left: 4px solid var(--medium); }
  .card.low      { border-left: 4px solid var(--low); }
  .card.info     { border-left: 4px solid var(--info); }
  .sev {
    display: inline-block;
    padding: .15rem .5rem;
    border-radius: 4px;
    font-size: .75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #fff;
  }
  .sev.critical { background: var(--critical); }
  .sev.high     { background: var(--high); }
  .sev.medium   { background: var(--medium); }
  .sev.low      { background: var(--low); }
  .sev.info     { background: var(--info); }
  .bar {
    height: 8px;
    background: var(--border);
    border-radius: 4px;
    overflow: hidden;
    margin-top: 4px;
  }
  .bar > div { height: 100%; background: var(--accent); }
  table { border-collapse: collapse; width: 100%; font-size: .9rem; }
  th, td { padding: .5rem .75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: .75rem; letter-spacing: 0.05em; }
  td code { font-family: "JetBrains Mono", "Menlo", monospace; font-size: .85rem; color: var(--muted); }
  .factor-row { display: grid; grid-template-columns: 140px 1fr 40px; gap: .75rem; align-items: center; margin-bottom: .4rem; }
  .factor-row .name { color: var(--muted); font-size: .85rem; }
  .factor-row .val  { text-align: right; font-variant-numeric: tabular-nums; }
  footer { margin-top: 2rem; color: var(--muted); font-size: .8rem; text-align: center; }
</style>
</head>
<body>
<header>
  <h1>{{.Title}}</h1>
  <div class="meta">Generated {{.GeneratedAt}} · schema html:v1 · {{.Count}} findings</div>
</header>

<section class="panel">
  <h2>Severity distribution</h2>
  <div class="totals">
    <div class="card critical"><div class="num">{{.Totals.Critical}}</div><div class="lbl">Critical</div></div>
    <div class="card high"><div class="num">{{.Totals.High}}</div><div class="lbl">High</div></div>
    <div class="card medium"><div class="num">{{.Totals.Medium}}</div><div class="lbl">Medium</div></div>
    <div class="card low"><div class="num">{{.Totals.Low}}</div><div class="lbl">Low</div></div>
    <div class="card info"><div class="num">{{.Totals.Info}}</div><div class="lbl">Info</div></div>
  </div>
</section>

{{if .TopFactors}}
<section class="panel">
  <h2>Top scoring factors (average across all findings)</h2>
  {{range .TopFactors}}
    <div class="factor-row">
      <div class="name">{{.Name}}</div>
      <div class="bar"><div style="width: {{.Average}}%"></div></div>
      <div class="val">{{.Average}}</div>
    </div>
  {{end}}
</section>
{{end}}

{{range .ByProtocol}}
<section class="panel">
  <h2>{{.Protocol}} · {{.Count}} findings · max {{.MaxScore}} · avg {{.AvgScore}}</h2>
  <table>
    <thead>
      <tr><th>Score</th><th>Severity</th><th>Finding ID</th><th>Target</th></tr>
    </thead>
    <tbody>
    {{- range .Findings }}
      <tr>
        <td><strong>{{.Score}}</strong></td>
        <td><span class="sev {{.Severity}}">{{.Severity}}</span></td>
        <td><code>{{.ID}}</code></td>
        <td><code>{{.TargetID}}</code></td>
      </tr>
    {{- end }}
    </tbody>
  </table>
</section>
{{end}}

<footer>ElSereno — ICS/OT exposure auditor · Report regenerated on demand from the run's findings table.</footer>
</body>
</html>
`
