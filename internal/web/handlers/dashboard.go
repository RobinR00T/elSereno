package handlers

import (
	"html/template"
	"net/http"
	"sort"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/web/httpctx"
)

// Dashboard returns the overview page. Single self-contained inline
// HTML: no external CSS/JS fetches, no framework. The live SSE
// feed (/api/v1/stream) keeps findings / runs / audit panels
// up-to-date without a full reload; the <meta refresh> fallback
// stays in place for clients that drop the EventSource connection.
// The template is inline on purpose; moving it to embed.FS lands
// once the findings / triage / runs DB panels stop being MVP.
func Dashboard() http.Handler {
	t := template.Must(template.New("overview").Parse(overviewHTML))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		data := overviewData()
		data.CSPNonce = httpctx.CSPNonce(r.Context())
		_ = t.Execute(w, data)
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
	// CSPNonce carries the per-request Content-Security-Policy
	// nonce so inline <script> and <style> tags that the template
	// emits are whitelisted by the CSP header set in
	// `web.securityHeaders`.
	CSPNonce string
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
<meta http-equiv="refresh" content="120">
<title>{{.Title}} · overview</title>
<style nonce="{{.CSPNonce}}">
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
  .feed {
    max-height: 300px;
    overflow-y: auto;
    font-family: "JetBrains Mono", Menlo, monospace;
    font-size: .8rem;
  }
  .feed .row {
    display: grid;
    grid-template-columns: auto auto 1fr;
    gap: .5rem;
    padding: .35rem 0;
    border-bottom: 1px dashed var(--border);
    align-items: baseline;
  }
  .feed .row:last-child { border-bottom: none; }
  .feed .ts { color: var(--muted); }
  .feed .kind {
    display: inline-block;
    padding: .05rem .4rem;
    border-radius: 3px;
    background: var(--accent-soft);
    color: var(--accent);
    font-size: .65rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .feed .kind.finding   { background: #fee2e2; color: var(--danger); }
  .feed .kind.run_start { background: #dcfce7; color: var(--ok); }
  .feed .kind.run_end   { background: #e0e7ff; color: #4f46e5; }
  .feed .body {
    color: var(--ink);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .live-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--ok);
    margin-right: .35rem;
    animation: pulse 2s infinite;
  }
  .live-dot.off { background: var(--muted); animation: none; }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  @media (prefers-color-scheme: dark) {
    .feed .kind.finding   { background: #3f1515; color: #f87171; }
    .feed .kind.run_start { background: #14321f; color: #4ade80; }
    .feed .kind.run_end   { background: #1a1f4a; color: #a5b4fc; }
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

    <section class="panel">
      <h2>Live feed <span id="live-status"><span class="live-dot off"></span><span id="live-label">connecting…</span></span></h2>
      <div class="sub">
        Streaming from <code>/api/v1/stream</code> via EventSource. Shows the last 50 events
        (findings, scan-run lifecycle, audit appends). Disconnected clients reconnect
        automatically after 3&nbsp;s.
      </div>
      <div id="feed" class="feed">
        <div class="row"><span class="ts">&mdash;</span><span class="kind">waiting</span><span class="body">No events yet. Run <code>elsereno scan</code> or any offensive verb to light this up.</span></div>
      </div>
    </section>

    <section class="panel placeholder">
      Findings / triage / runs tables load from the DB once the schema migration lands
      (v1.1 chunk 4, DB-backed half). The live feed above already tails everything the
      process publishes.
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
  ElSereno &mdash; ICS/OT exposure auditor &middot; Live SSE connected to <code>/api/v1/stream</code>; full reload every 2 min as fallback.
</footer>

<script nonce="{{.CSPNonce}}">
(function () {
  var feed = document.getElementById("feed");
  var statusDot = document.querySelector("#live-status .live-dot");
  var statusLabel = document.getElementById("live-label");
  var MAX_ROWS = 50;
  var first = true;

  function setStatus(ok, label) {
    statusDot.className = "live-dot" + (ok ? "" : " off");
    statusLabel.textContent = label;
  }

  function short(s, n) {
    if (!s) return "";
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function renderRow(kind, ts, body) {
    var row = document.createElement("div");
    row.className = "row";
    var t = document.createElement("span");
    t.className = "ts";
    t.textContent = ts;
    var k = document.createElement("span");
    k.className = "kind " + kind;
    k.textContent = kind;
    var b = document.createElement("span");
    b.className = "body";
    b.textContent = body;
    row.appendChild(t);
    row.appendChild(k);
    row.appendChild(b);
    if (first) {
      feed.innerHTML = "";
      first = false;
    }
    feed.insertBefore(row, feed.firstChild);
    while (feed.childElementCount > MAX_ROWS) {
      feed.removeChild(feed.lastChild);
    }
  }

  function bodyFor(kind, data) {
    try {
      if (kind === "finding") {
        return (data.severity || "?") + " · " + (data.protocol || "?") +
               " · score=" + (data.score != null ? data.score : "?") +
               " · id=" + short(data.id || "", 8);
      }
      if (kind === "run_start") {
        return "operator=" + (data.operator || "?") + " · id=" + short(data.run_id || "", 8);
      }
      if (kind === "run_end") {
        var counts = data.counts || {};
        var parts = Object.keys(counts).map(function (k) { return k + "=" + counts[k]; });
        return "status=" + (data.status || "?") + " · " + parts.join(" ");
      }
      if (kind === "audit") {
        return (data.event_type || "?") + " · actor=" + (data.actor || "?") +
               " · id=" + (data.id || "?");
      }
    } catch (e) {}
    return JSON.stringify(data).slice(0, 120);
  }

  function handle(kind, ev) {
    var data = {};
    try { data = JSON.parse(ev.data); } catch (e) {}
    var ts = new Date().toLocaleTimeString();
    renderRow(kind, ts, bodyFor(kind, data));
  }

  var es = new EventSource("/api/v1/stream");
  es.onopen = function () { setStatus(true, "live"); };
  es.onerror = function () { setStatus(false, "reconnecting…"); };
  ["finding", "run_start", "run_end", "audit"].forEach(function (kind) {
    es.addEventListener(kind, function (ev) { handle(kind, ev); });
  });
})();
</script>
</body>
</html>
`
