package handlers

import (
	"html/template"
	"net/http"

	"local/elsereno/internal/core"
)

// Dashboard returns the overview page. HTMX + small CSS only; no JS
// framework. The template is inline because the full embed.FS tree
// lands alongside F4's chunk-2 polish.
func Dashboard() http.Handler {
	t := template.Must(template.New("overview").Parse(overviewHTML))
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = t.Execute(w, overviewData())
	})
}

type overviewModel struct {
	Title   string
	Plugins []core.Plugin
}

func overviewData() overviewModel {
	return overviewModel{
		Title:   "ElSereno",
		Plugins: core.RegisteredPlugins(),
	}
}

const overviewHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
  :root { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  body { margin: 2rem; color: #111; max-width: 1000px; }
  h1 { margin-top: 0; }
  nav a { margin-right: 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ddd; padding: .4rem .6rem; text-align: left; }
  th { background: #f4f4f4; }
  code { font-family: "JetBrains Mono", Menlo, monospace; }
  .badge { display: inline-block; padding: .1rem .4rem; border: 1px solid #ccc; border-radius: 3px; font-size: .85em; }
  .default { background: #eef; }
  .offensive { background: #fee; }
</style>
</head>
<body>
<h1>{{.Title}}</h1>
<nav>
  <a href="/">Overview</a>
  <a href="/api/v1/plugins">API · plugins</a>
  <a href="/api/v1/scoring">API · scoring</a>
  <a href="/api/v1/health">API · health</a>
  <a href="/healthz">healthz</a>
  <a href="/readyz">readyz</a>
</nav>
<h2>Registered plugins</h2>
<table>
  <thead>
    <tr><th>Name</th><th>Description</th><th>Build</th><th>Default port</th></tr>
  </thead>
  <tbody>
  {{- range .Plugins }}
    <tr>
      <td><code>{{.Name}}</code></td>
      <td>{{.Description}}</td>
      <td><span class="badge {{.Build}}">{{.Build}}</span></td>
      <td>{{if .DefaultPort}}{{.DefaultPort}}{{else}}—{{end}}</td>
    </tr>
  {{- end }}
  </tbody>
</table>
<p><em>ElSereno F4 MVP dashboard. Live runs / findings / triage
views arrive alongside the DB-backed writer.</em></p>
</body>
</html>
`
