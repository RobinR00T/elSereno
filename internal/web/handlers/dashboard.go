package handlers

import (
	"html/template"
	"net/http"
	"sort"
	"time"

	"local/elsereno/internal/core"
)

// Dashboard returns the overview page. Single self-contained inline
// HTML: no external CSS/JS fetches, no framework. Auto-refreshes
// every 30 s while the DB-backed SSE stream is pending. The
// template is inline on purpose; moving it to embed.FS is F6+ once
// the findings / triage / runs panels stop being placeholders.
func Dashboard() http.Handler {
	t := template.Must(template.New("overview").Parse(overviewHTML))
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = t.Execute(w, overviewData())
	})
}

type overviewModel struct {
	Title            string
	GeneratedAt      string
	DefaultPlugins   []core.Plugin
	OffensivePlugins []core.Plugin
	Weights          map[string]float64
	Thresholds       map[string]int
	// WeightOrder + ThresholdOrder are pre-sorted slices so the
	// template renders deterministic output.
	WeightOrder    []string
	ThresholdOrder []string
}

// scoringDefaults mirrors the ADR-006 weights + thresholds served by
// /api/v1/scoring. Kept in sync by hand until the scoring engine's
// loader is wired into the dashboard.
var scoringDefaults = overviewScoring{
	Weights: map[string]float64{
		"protocol_risk": 0.25,
		"exposure":      0.20,
		"auth_state":    0.20,
		"capability":    0.15,
		"impact_class":  0.10,
		"cve_exposure":  0.10,
	},
	Thresholds: map[string]int{
		"critical": 80,
		"high":     60,
		"medium":   40,
		"low":      20,
	},
}

type overviewScoring struct {
	Weights    map[string]float64
	Thresholds map[string]int
}

func overviewData() overviewModel {
	all := core.RegisteredPlugins()
	var def, off []core.Plugin
	for _, p := range all {
		if p.Build == "offensive" {
			off = append(off, p)
		} else {
			def = append(def, p)
		}
	}
	sort.Slice(def, func(i, j int) bool { return def[i].Name < def[j].Name })
	sort.Slice(off, func(i, j int) bool { return off[i].Name < off[j].Name })

	weightKeys := make([]string, 0, len(scoringDefaults.Weights))
	for k := range scoringDefaults.Weights {
		weightKeys = append(weightKeys, k)
	}
	sort.Strings(weightKeys)
	thresholdOrder := []string{"critical", "high", "medium", "low"}

	return overviewModel{
		Title:            "ElSereno",
		GeneratedAt:      time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		DefaultPlugins:   def,
		OffensivePlugins: off,
		Weights:          scoringDefaults.Weights,
		Thresholds:       scoringDefaults.Thresholds,
		WeightOrder:      weightKeys,
		ThresholdOrder:   thresholdOrder,
	}
}

// overviewHTML is the inline single-file template. Dark-mode-aware
// palette matches the polished HTML report (F6 chunk 2).
const overviewHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>{{.Title}} · overview</title>
<style>
  :root {
    --bg: #f7f8fa;
    --panel: #ffffff;
    --ink: #111418;
    --muted: #6b7280;
    --border: #e5e7eb;
    --accent: #0f62fe;
    --accent-soft: #dbeafe;
    --ok: #059669;
    --danger: #dc2626;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0d10;
      --panel: #13161a;
      --ink: #e5e7eb;
      --muted: #9ca3af;
      --border: #2a2f37;
      --accent: #3b82f6;
      --accent-soft: #1e3a8a;
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
  header { margin-bottom: 1.5rem; }
  h1 { margin: 0 0 .25rem 0; font-size: 1.75rem; letter-spacing: -0.02em; }
  .meta { color: var(--muted); font-size: .9rem; }
  nav { margin: 1.25rem 0; display: flex; flex-wrap: wrap; gap: .75rem; }
  nav a {
    padding: .35rem .75rem;
    border: 1px solid var(--border);
    border-radius: 6px;
    background: var(--panel);
    color: var(--ink);
    text-decoration: none;
    font-size: .85rem;
  }
  nav a:hover { background: var(--accent-soft); border-color: var(--accent); }
  .grid {
    display: grid;
    grid-template-columns: 2fr 1fr;
    gap: 1.25rem;
  }
  @media (max-width: 900px) {
    .grid { grid-template-columns: 1fr; }
  }
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
  }
  .panel h2 { margin: 0 0 .75rem 0; font-size: 1.05rem; }
  .panel .sub { color: var(--muted); font-size: .8rem; margin-bottom: .75rem; }
  table { border-collapse: collapse; width: 100%; font-size: .9rem; }
  th, td { padding: .5rem .75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: .7rem; letter-spacing: 0.05em; }
  code { font-family: "JetBrains Mono", Menlo, monospace; font-size: .85em; color: var(--muted); }
  .badge {
    display: inline-block;
    padding: .1rem .5rem;
    border-radius: 4px;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }
  .badge.default { background: var(--accent-soft); color: var(--accent); }
  .badge.offensive { background: #fee2e2; color: var(--danger); }
  @media (prefers-color-scheme: dark) {
    .badge.offensive { background: #3f1515; color: #f87171; }
  }
  .kv { display: grid; grid-template-columns: 1fr auto; gap: .25rem 1rem; font-size: .9rem; }
  .kv .k { color: var(--muted); }
  .kv .v { font-variant-numeric: tabular-nums; text-align: right; }
  .sev-chip {
    display: inline-block;
    padding: .1rem .5rem;
    border-radius: 4px;
    color: #fff;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .sev-chip.critical { background: #dc2626; }
  .sev-chip.high     { background: #ea580c; }
  .sev-chip.medium   { background: #d97706; }
  .sev-chip.low      { background: #059669; }
  .placeholder {
    border: 2px dashed var(--border);
    background: transparent;
    color: var(--muted);
    text-align: center;
    padding: 1.5rem;
  }
  footer {
    margin-top: 2rem;
    color: var(--muted);
    font-size: .8rem;
    text-align: center;
  }
  .ok-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--ok); margin-right: .35rem; }
</style>
</head>
<body>
<header>
  <h1>{{.Title}}</h1>
  <div class="meta"><span class="ok-dot"></span>Overview · refreshed {{.GeneratedAt}}</div>
</header>

<nav>
  <a href="/">Overview</a>
  <a href="/admin/security">Security self-audit</a>
  <a href="/api/v1/plugins">API · plugins</a>
  <a href="/api/v1/scoring">API · scoring</a>
  <a href="/api/v1/health">API · health</a>
  <a href="/api/v1/openapi.yaml">OpenAPI</a>
  <a href="/healthz">healthz</a>
  <a href="/readyz">readyz</a>
</nav>

<div class="grid">
  <div>
    <section class="panel">
      <h2>Default plugins <span class="badge default">{{len .DefaultPlugins}} registered</span></h2>
      <div class="sub">Read-only in the default build. Wire-layer write-ban applies to every TCP plugin.</div>
      <table>
        <thead><tr><th>Name</th><th>Description</th><th>Port</th></tr></thead>
        <tbody>
        {{- range .DefaultPlugins }}
          <tr>
            <td><code>{{.Name}}</code></td>
            <td>{{.Description}}</td>
            <td>{{if .DefaultPort}}{{.DefaultPort}}{{else}}&mdash;{{end}}</td>
          </tr>
        {{- end }}
        </tbody>
      </table>
    </section>

    {{if .OffensivePlugins}}
    <section class="panel">
      <h2>Offensive plugins <span class="badge offensive">-tags offensive</span></h2>
      <div class="sub">Gated by ADR-039 triple-confirm (build tag + --accept-writes + --confirm-target + HMAC token).</div>
      <table>
        <thead><tr><th>Name</th><th>Description</th><th>Port</th></tr></thead>
        <tbody>
        {{- range .OffensivePlugins }}
          <tr>
            <td><code>{{.Name}}</code></td>
            <td>{{.Description}}</td>
            <td>{{if .DefaultPort}}{{.DefaultPort}}{{else}}&mdash;{{end}}</td>
          </tr>
        {{- end }}
        </tbody>
      </table>
    </section>
    {{end}}

    <section class="panel placeholder">
      Findings / triage / runs panels arrive with the DB-backed writer (F6+).<br>
      Live SSE feed on <code>/api/v1/stream</code> is queued for the same chunk.
    </section>
  </div>

  <aside>
    <section class="panel">
      <h2>Scoring weights <span class="sub">ADR-006</span></h2>
      <div class="kv">
        {{- range .WeightOrder }}
        <div class="k">{{.}}</div>
        <div class="v">{{index $.Weights .}}</div>
        {{- end }}
      </div>
    </section>
    <section class="panel">
      <h2>Severity thresholds</h2>
      <div class="kv">
        {{- range .ThresholdOrder }}
        <div class="k"><span class="sev-chip {{.}}">{{.}}</span></div>
        <div class="v">&ge; {{index $.Thresholds .}}</div>
        {{- end }}
      </div>
    </section>
    <section class="panel">
      <h2>Vault</h2>
      <div class="meta">
        Serve requires a vault unlocked via <code>elsereno vault unlock</code> or
        <code>--vault-passphrase-file &lt;0600 path&gt;</code> (ADR-026).
      </div>
    </section>
    <section class="panel">
      <h2>Build</h2>
      <div class="kv">
        <div class="k">Schema</div><div class="v"><code>api:v1</code></div>
        <div class="k">Plugins</div><div class="v">{{len .DefaultPlugins}} default &middot; {{len .OffensivePlugins}} offensive</div>
        <div class="k">Tag</div><div class="v">{{if .OffensivePlugins}}offensive{{else}}default{{end}}</div>
      </div>
    </section>
  </aside>
</div>

<footer>
  ElSereno &mdash; ICS/OT exposure auditor &middot; Page auto-refreshes every 30 s pending live SSE.
</footer>
</body>
</html>
`
