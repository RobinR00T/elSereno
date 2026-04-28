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
  .triage {
    display: flex;
    flex-wrap: wrap;
    gap: .5rem;
    align-items: center;
  }
  .triage .bucket {
    display: inline-flex;
    align-items: baseline;
    gap: .5rem;
    padding: .35rem .75rem;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--panel);
    font-size: .85rem;
  }
  .triage .bucket .count {
    font-weight: 700;
    font-variant-numeric: tabular-nums;
    font-size: 1rem;
  }
  .triage-empty { color: var(--muted); font-size: .9rem; }
  table.findings-table, table#findings-table, table#runs-table {
    font-variant-numeric: tabular-nums;
  }
  #findings-table tbody tr.empty td,
  #runs-table tbody tr.empty td {
    text-align: center;
    color: var(--muted);
    font-style: italic;
  }
  #findings-table td.fid code,
  #runs-table td.rid code {
    font-size: .75em;
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

    <section class="panel">
      <h2>Triage <span class="sub" id="triage-sub">loading…</span></h2>
      <div id="triage" class="triage">
        <div class="triage-empty">No findings yet. Panels populate once the DB pool is wired and findings land.</div>
      </div>
    </section>

    <section class="panel">
      <h2>Recent findings <span class="sub">newest first · top 50</span></h2>
      <div class="sub">
        Loaded from <code>/api/v1/findings</code>. Returns 503 if
        <code>DATABASE_URL</code> isn't set; panel stays empty in that case.
        v1.18+: <a id="findings-csv" href="/api/v1/findings?format=csv&amp;limit=500" download>Download CSV (top 500)</a>
      </div>
      <table id="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Protocol</th>
            <th>Score</th>
            <th>Created</th>
            <th>Finding</th>
          </tr>
        </thead>
        <tbody id="findings-body">
          <tr class="empty"><td colspan="5">loading…</td></tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Recent runs <span class="sub">newest first · top 20</span></h2>
      <table id="runs-table">
        <thead>
          <tr>
            <th>Status</th>
            <th>Operator</th>
            <th>Started</th>
            <th>Findings</th>
            <th>Run ID</th>
          </tr>
        </thead>
        <tbody id="runs-body">
          <tr class="empty"><td colspan="5">loading…</td></tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Reload cadence <span class="sub">v1.19+ · proxy_allowlist_reload · last 7 days</span></h2>
      <div class="sub">
        Per-day count of v1.17-chunk-5 SIGUSR1 reload audit
        entries. Spikes correlate to operator change-window
        activity; sustained zeroes mean no in-process reloads.
        Loaded from <code>/api/v1/audit/cadence</code>.
      </div>
      <table id="reload-cadence-table">
        <thead>
          <tr><th>Day (UTC)</th><th>Event</th><th>Count</th><th>Bar</th></tr>
        </thead>
        <tbody id="reload-cadence-body">
          <tr class="empty"><td colspan="4">loading…</td></tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Audit feed <span class="sub">v1.19+ · newest first · top 50</span></h2>
      <div class="sub">
        Loaded from <code>/api/v1/audit</code>. Filter by event_type or actor.
        Tombstoned rows show as <em>[redacted]</em>; the chain entry stays.
      </div>
      <form id="audit-filter" onsubmit="return refreshAudit(event);" style="margin: 0.5em 0;">
        <label>event_type:
          <select id="audit-event-type">
            <option value="">— any —</option>
            <option value="vault_unlock">vault_unlock</option>
            <option value="vault_lock">vault_lock</option>
            <option value="serve_start">serve_start</option>
            <option value="offensive_write">offensive_write</option>
            <option value="offensive_dial">offensive_dial</option>
            <option value="offensive_harvest">offensive_harvest</option>
            <option value="offensive_sandbox">offensive_sandbox</option>
            <option value="proxy_allowlist_reload">proxy_allowlist_reload</option>
            <option value="protocol_probe">protocol_probe</option>
            <option value="scope_applied">scope_applied</option>
            <option value="token_rotate">token_rotate</option>
            <option value="admin_action">admin_action</option>
          </select>
        </label>
        &nbsp;
        <label>actor: <input type="text" id="audit-actor" size="20" placeholder="any"></label>
        &nbsp;
        <button type="submit">Refresh</button>
      </form>
      <table id="audit-table">
        <thead>
          <tr>
            <th>Occurred</th>
            <th>Event</th>
            <th>Actor</th>
            <th>Payload (excerpt)</th>
          </tr>
        </thead>
        <tbody id="audit-body">
          <tr class="empty"><td colspan="4">loading…</td></tr>
        </tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Diff between runs <span class="sub">v1.18+ · what changed</span></h2>
      <div class="sub">
        Compare two runs by ID. Match key is (target, protocol):
        rediscovered exposures land in <em>persisting</em>, fixed
        ones in <em>resolved</em>, fresh ones in <em>new</em>.
      </div>
      <form id="diff-form" onsubmit="return runDiff(event);" style="margin: 0.5em 0;">
        <label>Old run: <input type="text" id="diff-old" size="36" placeholder="run id" required></label>
        &nbsp;
        <label>New run: <input type="text" id="diff-new" size="36" placeholder="run id" required></label>
        &nbsp;
        <button type="submit">Diff</button>
      </form>
      <div id="diff-result" class="sub">No diff requested yet.</div>
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

  // --- DB panels: triage / findings / runs -----------------
  //
  // Each panel polls its endpoint once on page load + on every
  // relevant SSE event (finding / run_*). Panels fall back to a
  // "backend unavailable" message when the endpoint returns 503
  // (DATABASE_URL not set at serve-start).
  function fetchJSON(path) {
    return fetch(path, {credentials: "same-origin"}).then(function (r) {
      if (r.status === 503) return {unavailable: true};
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }
  function escText(s) {
    var div = document.createElement("div");
    div.textContent = (s == null ? "" : String(s));
    return div.innerHTML;
  }
  function renderTriage() {
    fetchJSON("/api/v1/triage").then(function (res) {
      var host = document.getElementById("triage");
      var sub = document.getElementById("triage-sub");
      if (!host) return;
      host.innerHTML = "";
      if (res.unavailable) {
        sub.textContent = "backend unavailable";
        host.innerHTML = '<div class="triage-empty">DB pool not configured; set <code>DATABASE_URL</code> and restart.</div>';
        return;
      }
      var buckets = (res.data || []);
      if (buckets.length === 0) {
        sub.textContent = "no findings";
        host.innerHTML = '<div class="triage-empty">Run <code>elsereno scan</code> to seed findings.</div>';
        return;
      }
      sub.textContent = "updated " + new Date().toLocaleTimeString();
      buckets.forEach(function (b) {
        var el = document.createElement("span");
        el.className = "bucket";
        el.innerHTML = '<span class="sev-chip ' + escText(b.severity) + '">' + escText(b.severity) + '</span>' +
                       '<span class="count">' + escText(b.count) + '</span>';
        host.appendChild(el);
      });
    }).catch(function (e) {
      var sub = document.getElementById("triage-sub");
      if (sub) sub.textContent = "error: " + e.message;
    });
  }
  function renderFindings() {
    fetchJSON("/api/v1/findings?limit=50").then(function (res) {
      var body = document.getElementById("findings-body");
      if (!body) return;
      if (res.unavailable) {
        body.innerHTML = '<tr class="empty"><td colspan="5">backend unavailable (no DATABASE_URL)</td></tr>';
        return;
      }
      var rows = res.data || [];
      if (rows.length === 0) {
        body.innerHTML = '<tr class="empty"><td colspan="5">no findings yet</td></tr>';
        return;
      }
      body.innerHTML = rows.map(function (f) {
        return '<tr>' +
          '<td><span class="sev-chip ' + escText(f.severity) + '">' + escText(f.severity) + '</span></td>' +
          '<td><code>' + escText(f.protocol) + '</code></td>' +
          '<td>' + escText(f.score) + '</td>' +
          '<td>' + escText(new Date(f.created_at).toLocaleString()) + '</td>' +
          '<td class="fid"><code>' + escText((f.id || "").slice(0, 8)) + '</code></td>' +
        '</tr>';
      }).join("");
    }).catch(function (e) {
      var body = document.getElementById("findings-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="5">error: ' + escText(e.message) + '</td></tr>';
    });
  }
  function renderRuns() {
    fetchJSON("/api/v1/runs?limit=20").then(function (res) {
      var body = document.getElementById("runs-body");
      if (!body) return;
      if (res.unavailable) {
        body.innerHTML = '<tr class="empty"><td colspan="5">backend unavailable (no DATABASE_URL)</td></tr>';
        return;
      }
      var rows = res.data || [];
      if (rows.length === 0) {
        body.innerHTML = '<tr class="empty"><td colspan="5">no runs yet</td></tr>';
        return;
      }
      body.innerHTML = rows.map(function (r) {
        return '<tr>' +
          '<td>' + escText(r.status) + '</td>' +
          '<td>' + escText(r.operator || "—") + '</td>' +
          '<td>' + escText(new Date(r.started_at).toLocaleString()) + '</td>' +
          '<td>' + escText(r.findings) + '</td>' +
          '<td class="rid"><code>' + escText((r.id || "").slice(0, 8)) + '</code></td>' +
        '</tr>';
      }).join("");
    }).catch(function (e) {
      var body = document.getElementById("runs-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="5">error: ' + escText(e.message) + '</td></tr>';
    });
  }

  // v1.19 chunk 2: reload cadence summary. Per-day count of
  // proxy_allowlist_reload events for the last 7 days, with a
  // text-based bar chart so operators see spikes at a glance
  // without pulling in a chart library.
  function renderReloadCadence() {
    fetchJSON("/api/v1/audit/cadence?event_type=proxy_allowlist_reload&days=7").then(function (res) {
      var body = document.getElementById("reload-cadence-body");
      if (!body) return;
      if (res.unavailable) { body.innerHTML = '<tr class="empty"><td colspan="4">backend unavailable (no DATABASE_URL)</td></tr>'; return; }
      var rows = res.data || [];
      if (rows.length === 0) { body.innerHTML = '<tr class="empty"><td colspan="4">no reload audit rows in the last 7 days</td></tr>'; return; }
      // Find the max for bar scaling.
      var maxN = 0;
      rows.forEach(function (r) { if (r.count > maxN) maxN = r.count; });
      body.innerHTML = rows.map(function (r) {
        var dayLabel = (r.day || "").slice(0, 10);
        var bar = makeAsciiBar(r.count, maxN);
        return '<tr>' +
          '<td>' + escText(dayLabel) + '</td>' +
          '<td><code>' + escText(r.event_type) + '</code></td>' +
          '<td>' + escText(r.count) + '</td>' +
          '<td><code>' + escText(bar) + '</code></td>' +
        '</tr>';
      }).join("");
    }).catch(function (e) {
      var body = document.getElementById("reload-cadence-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="4">error: ' + escText(e.message) + '</td></tr>';
    });
  }
  function makeAsciiBar(count, max) {
    if (max <= 0) return "";
    var width = 30;
    var n = Math.round((count / max) * width);
    if (n < 1 && count > 0) n = 1;
    var s = "";
    for (var i = 0; i < n; i++) s += "█";
    return s;
  }

  // v1.19 chunk 1: audit feed. Loads /api/v1/audit, applying
  // event_type + actor filters from the form. Tombstoned rows
  // render as [redacted] per ADR-013.
  function refreshAudit(ev) {
    if (ev) ev.preventDefault();
    var eventType = (document.getElementById("audit-event-type") || {}).value || "";
    var actor = ((document.getElementById("audit-actor") || {}).value || "").trim();
    var url = "/api/v1/audit?limit=50";
    if (eventType) url += "&event_type=" + encodeURIComponent(eventType);
    if (actor) url += "&actor=" + encodeURIComponent(actor);
    fetchJSON(url).then(function (res) {
      var body = document.getElementById("audit-body");
      if (!body) return;
      if (res.unavailable) { body.innerHTML = '<tr class="empty"><td colspan="4">backend unavailable (no DATABASE_URL)</td></tr>'; return; }
      var rows = res.data || [];
      if (rows.length === 0) { body.innerHTML = '<tr class="empty"><td colspan="4">no audit rows</td></tr>'; return; }
      body.innerHTML = rows.map(function (r) {
        var when = new Date(r.occurred_at).toLocaleString();
        var payloadCell = r.tombstoned ? '<em>[redacted]</em>' : escText(payloadExcerpt(r.payload));
        return '<tr>' +
          '<td>' + escText(when) + '</td>' +
          '<td><code>' + escText(r.event_type) + '</code></td>' +
          '<td>' + escText(r.actor) + '</td>' +
          '<td class="rid">' + payloadCell + '</td>' +
        '</tr>';
      }).join("");
    }).catch(function (e) {
      var body = document.getElementById("audit-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="4">error: ' + escText(e.message) + '</td></tr>';
    });
    return false;
  }
  function payloadExcerpt(p) {
    // p is JSON; render up to 120 chars to keep the row narrow.
    if (p == null) return "";
    var s = (typeof p === "string") ? p : JSON.stringify(p);
    if (s.length > 120) s = s.slice(0, 117) + "…";
    return s;
  }

  // v1.18 chunk 2: diff between runs. Operator types two run
  // IDs; we hit /api/v1/findings/diff and render new /
  // resolved / persisting buckets in the panel below the form.
  function runDiff(ev) {
    ev.preventDefault();
    var oldRun = document.getElementById("diff-old").value.trim();
    var newRun = document.getElementById("diff-new").value.trim();
    var out = document.getElementById("diff-result");
    if (!oldRun || !newRun) { out.textContent = "both run IDs are required"; return false; }
    if (oldRun === newRun) { out.textContent = "old and new must be distinct run IDs"; return false; }
    out.innerHTML = "computing diff…";
    fetchJSON("/api/v1/findings/diff?old=" + encodeURIComponent(oldRun) + "&new=" + encodeURIComponent(newRun))
      .then(function (res) {
        if (res.unavailable) { out.textContent = "backend unavailable (no DATABASE_URL)"; return; }
        var d = res.data || {};
        var n = (d.new || []).length;
        var r = (d.resolved || []).length;
        var p = (d.persisting || []).length;
        out.innerHTML =
          '<strong>new:</strong> ' + n + ' &nbsp; ' +
          '<strong>resolved:</strong> ' + r + ' &nbsp; ' +
          '<strong>persisting:</strong> ' + p +
          renderDiffSection("New (added)", d.new) +
          renderDiffSection("Resolved (fixed)", d.resolved) +
          renderDiffSection("Persisting", d.persisting);
      })
      .catch(function (e) { out.textContent = "error: " + e.message; });
    return false;
  }
  function renderDiffSection(label, rows) {
    if (!rows || rows.length === 0) return '';
    var trs = rows.map(function (f) {
      return '<tr>' +
        '<td><span class="sev-chip ' + escText(f.severity) + '">' + escText(f.severity) + '</span></td>' +
        '<td>' + escText(f.protocol) + '</td>' +
        '<td>' + escText(f.score) + '</td>' +
        '<td>' + escText(f.target_id) + '</td>' +
      '</tr>';
    }).join("");
    return '<h4>' + escText(label) + ' (' + rows.length + ')</h4>' +
      '<table class="findings-table"><thead><tr><th>Severity</th><th>Protocol</th><th>Score</th><th>Target</th></tr></thead><tbody>' +
      trs + '</tbody></table>';
  }

  // Initial load.
  renderTriage(); renderFindings(); renderRuns(); refreshAudit(); renderReloadCadence();

  // Re-fetch the DB-backed panels on SSE signals so the page
  // reacts to live scans without a full reload. We debounce by
  // 500ms so a burst of findings doesn't hammer the DB.
  var refreshTimer = null;
  function scheduleRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = setTimeout(function () {
      renderTriage(); renderFindings(); renderRuns();
      refreshTimer = null;
    }, 500);
  }
  es.addEventListener("finding", scheduleRefresh);
  es.addEventListener("run_start", scheduleRefresh);
  es.addEventListener("run_end", scheduleRefresh);
})();
</script>
</body>
</html>
`
