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

    <section class="panel" id="scans-panel">
      <h2>Scan jobs <span class="sub" id="scans-sub">v1.62 · trigger + monitor · newest first</span></h2>
      <div class="sub">
        Submit a scan job; the worker (configured via
        <code>serve --scan-store</code> + <code>--scan-pool</code>)
        picks it up, runs the named plugin against the parsed
        targets, and the row updates as state advances
        (<code>queued → running → completed</code>). Backed by
        <code>POST/GET /api/v1/scans/</code>.
      </div>
      <form id="scan-submit-form" onsubmit="return submitScan(event);" style="margin: 0.5em 0; display: flex; flex-wrap: wrap; gap: 0.5em; align-items: end;">
        <label>input:
          <input type="text" id="scan-input" placeholder="list:targets.txt | stdin | internetdb:1.2.3.4" size="40" required />
        </label>
        <label>plugin(s):
          <input type="text" id="scan-plugin" placeholder="modbus,s7  (blank = all)" size="22"
            list="scan-plugin-options" autocomplete="off" />
          <datalist id="scan-plugin-options"></datalist>
        </label>
        <label>default port:
          <input type="number" id="scan-default-port" min="0" max="65535" value="0" size="6" />
        </label>
        <button type="submit">Submit</button>
        <button type="button" onclick="toggleBulkPanel()" id="scan-bulk-toggle" class="sub">Bulk…</button>
        <span id="scan-submit-status" class="sub" style="margin-left: 0.5em;"></span>
      </form>

      <!-- v1.69: bulk submit panel. Hidden by default; the
           Bulk… button toggles it. Shares plugin + default-port
           with the single-submit form so the operator sets them
           once. -->
      <div id="scan-bulk-panel" style="display: none; margin: 0.5em 0; padding: 0.5em; border: 1px dashed #888; border-radius: 4px;">
        <div class="sub" style="margin-bottom: 0.5em;">
          One input per line. Plugin(s) + default port are
          taken from the form above. Capped at 200 inputs per
          submit; partial failures (empty lines, malformed
          inputs) are reported in the response.
        </div>
        <textarea id="scan-bulk-inputs" rows="6" cols="60"
          placeholder="list:t1.txt&#10;list:t2.txt&#10;internetdb:1.2.3.0/24" style="font-family: monospace;"></textarea>
        <div style="margin-top: 0.5em; display: flex; gap: 0.5em; align-items: center;">
          <button type="button" onclick="bulkSubmitScan()">Bulk submit</button>
          <span id="scan-bulk-status" class="sub"></span>
        </div>
      </div>
      <table id="scans-table">
        <thead>
          <tr>
            <th>State</th>
            <th>Operator</th>
            <th>Plugin</th>
            <th>Input</th>
            <th>Targets / Findings</th>
            <th>Created</th>
            <th>Job ID</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="scans-body">
          <tr class="empty"><td colspan="8">loading…</td></tr>
        </tbody>
      </table>
    </section>

    <!-- v1.72: scheduled scans. Saved Job templates that
         fire automatically on a fixed interval. -->
    <section class="panel" id="schedules-panel">
      <h2>Scheduled scans <span class="sub">v1.70+ · /api/v1/schedules</span></h2>
      <div class="sub">
        Saved Job templates that fire on an interval.
        Useful for "scan my fleet every 6h" workflows.
        Backed by either MemoryScheduleStore
        (--scan-store=memory; lost on restart) or
        DBScheduleStore (--scan-store=db; survives
        restart, requires migration 00007).
      </div>
      <!-- v1.95: bulk pause/resume for planned maintenance. -->
      <div style="margin: 0.4em 0; display: flex; gap: 0.4em; align-items: center;">
        <button type="button" onclick="bulkScheduleEnable(false)" title="Disable every schedule (writes audit per state change).">Pause All</button>
        <button type="button" onclick="bulkScheduleEnable(true)" title="Re-enable every schedule.">Resume All</button>
        <span id="schedule-bulk-status" class="sub"></span>
      </div>
      <form id="schedule-submit-form" onsubmit="return submitSchedule(event);" style="margin: 0.5em 0; display: flex; flex-wrap: wrap; gap: 0.5em; align-items: end;">
        <label>name:
          <input type="text" id="schedule-name" placeholder="every-6h" size="20" required />
        </label>
        <label>input:
          <input type="text" id="schedule-input" placeholder="list:fleet.txt" size="32" required />
        </label>
        <label>plugin(s):
          <input type="text" id="schedule-plugin" placeholder="modbus,s7  (blank = all)" size="22"
            list="scan-plugin-options" autocomplete="off" />
        </label>
        <label>cadence:
          <select id="schedule-cadence-mode" onchange="onScheduleCadenceModeChange()">
            <option value="interval" selected>interval</option>
            <option value="cron">cron</option>
          </select>
        </label>
        <label id="schedule-interval-label">interval (s):
          <input type="number" id="schedule-interval" min="60" max="604800" value="3600" size="8" />
        </label>
        <label id="schedule-cron-label" style="display: none;">cron:
          <input type="text" id="schedule-cron" placeholder="0 2 * * * | @daily" size="22" />
        </label>
        <label id="schedule-timezone-label" style="display: none;">timezone:
          <input type="text" id="schedule-timezone" placeholder="UTC | America/New_York" size="20" autocomplete="off" />
        </label>
        <label title="v1.89+ per-schedule audit retention override. 0 = inherit global --audit-retention-days.">audit days:
          <input type="number" id="schedule-audit-retention-days" min="0" max="3650" value="0" size="6" />
        </label>
        <button type="submit" id="schedule-submit-button">Create</button>
        <button type="button" id="schedule-cancel-button" onclick="cancelEditSchedule()" style="display: none;">Cancel</button>
        <button type="button" id="schedule-preview-button" onclick="previewNextFire()" style="margin-left: 0.5em;">Preview next fire</button>
        <span id="schedule-submit-status" class="sub" style="margin-left: 0.5em;"></span>
        <div id="schedule-next-fire-preview" class="sub" style="margin-top: 0.3em;"></div>
        <div id="schedule-merge-view" style="display: none; margin-top: 0.5em; padding: 0.5em; border: 1px solid #c66; background: #fee;">
          <strong>Schedule was modified by another operator.</strong>
          <div class="sub">Pick a side per field (mine = your pending edit · server = freshly fetched value):</div>
          <ul id="schedule-merge-diff" style="margin: 0.3em 0; list-style: none; padding-left: 0;"></ul>
          <button type="button" id="schedule-apply-selected-button" onclick="applySelectedMerge()">Apply selected (per-field)</button>
          <button type="button" id="schedule-accept-server-button" onclick="acceptServerSchedule()" style="margin-left: 0.5em;">Take server (discard my edits)</button>
          <button type="button" id="schedule-force-overwrite-button" onclick="forceOverwriteSchedule()" style="margin-left: 0.5em;">Force overwrite (re-submit ignoring If-Match)</button>
        </div>
      </form>
      <table id="schedules-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Input</th>
            <th>Plugins</th>
            <th>Interval</th>
            <th>State</th>
            <th>Last fired</th>
            <th>Next fire</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="schedules-body">
          <tr class="empty"><td colspan="8">loading…</td></tr>
        </tbody>
      </table>
      <div id="schedule-audit-view" style="display: none; margin-top: 0.6em; padding: 0.5em; border: 1px solid #aaa; background: #f6f6f6;">
        <h3 style="margin: 0 0 0.3em;">Audit history</h3>
        <div class="sub" id="schedule-audit-subtitle"></div>
        <table id="schedule-audit-table" style="margin-top: 0.3em;">
          <thead>
            <tr><th>When</th><th>Who</th><th>Event</th><th>Changes</th></tr>
          </thead>
          <tbody id="schedule-audit-body">
            <tr class="empty"><td colspan="4">loading…</td></tr>
          </tbody>
        </table>
        <button type="button" id="schedule-audit-close-button" onclick="closeAuditView()" style="margin-top: 0.3em;">Close</button>
      </div>
      <!-- v1.92: per-schedule run history. Loaded on demand from
           /api/v1/schedules/{id}/runs. Empty until openRunsView fires. -->
      <div id="schedule-runs-view" style="display: none; margin-top: 0.6em; padding: 0.5em; border: 1px solid #aaa; background: #f6f6f6;">
        <h3 style="margin: 0 0 0.3em;">Run history</h3>
        <div class="sub" id="schedule-runs-subtitle"></div>
        <table id="schedule-runs-table" style="margin-top: 0.3em;">
          <thead>
            <tr><th>When</th><th>State</th><th>Job ID</th><th>Findings</th><th>Targets</th></tr>
          </thead>
          <tbody id="schedule-runs-body">
            <tr class="empty"><td colspan="5">loading…</td></tr>
          </tbody>
        </table>
        <button type="button" id="schedule-runs-close-button" onclick="closeRunsView()" style="margin-top: 0.3em;">Close</button>
      </div>
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

  // v1.62: scan-jobs panel renderer + submit + cancel.
  // Polls /api/v1/scans every 2s while any job is non-terminal,
  // backs off to 10s when all jobs are terminal so an idle
  // dashboard doesn't hammer the API.
  var scansPollTimer = null;
  function scheduleScansPoll(delayMs) {
    if (scansPollTimer) clearTimeout(scansPollTimer);
    scansPollTimer = setTimeout(renderScans, delayMs);
  }
  function renderScans() {
    fetchJSON("/api/v1/scans?limit=20").then(function (res) {
      var body = document.getElementById("scans-body");
      if (!body) return;
      if (res.unavailable) {
        body.innerHTML = '<tr class="empty"><td colspan="8">scan orchestration disabled (start serve with --scan-store=memory or =db)</td></tr>';
        scheduleScansPoll(10000);
        return;
      }
      var rows = res.data || [];
      if (rows.length === 0) {
        body.innerHTML = '<tr class="empty"><td colspan="8">no jobs yet — submit one above</td></tr>';
        scheduleScansPoll(10000);
        return;
      }
      var anyActive = false;
      body.innerHTML = rows.map(function (j) {
        var state = j.state || "?";
        if (state === "queued" || state === "running") anyActive = true;
        var plugins = (j.plugins || []).join(",") || "—";
        var stats = j.stats || {};
        var statsCell = (stats.targets_seen || 0) + "/" + (stats.targets_scanned || 0) +
          " · " + (stats.findings_count || 0) + " findings";
        // v1.66: per-plugin breakdown as a title= tooltip.
        // Format: "modbus: 3, s7: 2" (plugin: count pairs).
        var byPlugin = j.findings_by_plugin || {};
        var breakdown = Object.keys(byPlugin)
          .sort()
          .map(function (k) { return k + ": " + byPlugin[k]; })
          .join(", ");
        var statsAttrs = breakdown ? ' title="' + escAttr(breakdown) + '"' : "";
        var idShort = (j.id || "").slice(0, 8);
        var action = "";
        if (state === "queued" || state === "running") {
          action = '<button type="button" data-job-id="' + escAttr(j.id) +
            '" onclick="cancelScan(this.dataset.jobId)">Cancel</button>';
        } else {
          action = '<span class="sub">' + escText(j.error ? "err" : "—") + '</span>';
        }
        return '<tr data-scan-id="' + escAttr(j.id || "") + '">' +
          '<td><code class="state-' + escAttr(state) + '">' + escText(state) + '</code></td>' +
          '<td>' + escText(j.operator || "—") + '</td>' +
          '<td><code>' + escText(plugins) + '</code></td>' +
          '<td><code>' + escText(j.input || "") + '</code></td>' +
          '<td data-scan-stats' + statsAttrs + '>' + escText(statsCell) + '</td>' +
          '<td>' + escText(j.created_at ? new Date(j.created_at).toLocaleString() : "") + '</td>' +
          '<td class="rid"><code>' + escText(idShort) + '</code></td>' +
          '<td>' + action + '</td>' +
          '</tr>';
      }).join("");
      // Active jobs: poll fast. Idle: back off.
      scheduleScansPoll(anyActive ? 2000 : 10000);
    }).catch(function (e) {
      var body = document.getElementById("scans-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="8">error: ' + escText(e.message) + '</td></tr>';
      scheduleScansPoll(10000);
    });
  }
  function submitScan(ev) {
    if (ev) ev.preventDefault();
    var input = (document.getElementById("scan-input") || {}).value || "";
    var pluginRaw = (document.getElementById("scan-plugin") || {}).value || "";
    var dpRaw = (document.getElementById("scan-default-port") || {}).value || "0";
    var status = document.getElementById("scan-submit-status");
    var defaultPort = parseInt(dpRaw, 10);
    if (!isFinite(defaultPort) || defaultPort < 0) defaultPort = 0;
    // v1.64: comma-separated plugin list. Blank = run all
    // registered plugins (the runner picks per-target by
    // DefaultPort match).
    var plugins = pluginRaw.split(",").map(function (s) {
      return s.trim();
    }).filter(function (s) {
      return s.length > 0;
    });
    var body = JSON.stringify({
      input: input,
      plugins: plugins,
      default_port: defaultPort
    });
    if (status) status.textContent = "submitting…";
    fetch("/api/v1/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: body,
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      var j = (res && res.data) || {};
      if (status) status.textContent = "queued · " + (j.id || "").slice(0, 8);
      // Clear inputs that are scan-specific; keep input + plugin
      // so the operator can submit more variants quickly.
      // Refresh the table immediately.
      renderScans();
    }).catch(function (e) {
      if (status) status.textContent = "error: " + e.message;
    });
    return false;
  }
  function cancelScan(jobID) {
    if (!jobID) return;
    fetch("/api/v1/scans/" + encodeURIComponent(jobID) + "/cancel", {
      method: "POST",
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      renderScans();
    }).catch(function (e) {
      var status = document.getElementById("scan-submit-status");
      if (status) status.textContent = "cancel error: " + e.message;
    });
  }
  // escAttr is for HTML attribute contexts (data-*, id, etc.).
  // It's a stricter variant of escText that drops anything not
  // safe for an unquoted attribute.
  function escAttr(s) {
    return String(s == null ? "" : s).replace(/[^A-Za-z0-9._-]/g, "");
  }
  // v1.69: bulk-submit panel. Toggle visibility + collect the
  // textarea lines + POST to /scans/bulk. Reuses the form's
  // plugin + default_port fields so the operator sets them
  // once and applies to every line.
  function toggleBulkPanel() {
    var panel = document.getElementById("scan-bulk-panel");
    if (!panel) return;
    panel.style.display = panel.style.display === "none" ? "block" : "none";
  }
  function bulkSubmitScan() {
    var ta = document.getElementById("scan-bulk-inputs");
    var status = document.getElementById("scan-bulk-status");
    if (!ta) return;
    var lines = (ta.value || "").split(/\r?\n/)
      .map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
    if (lines.length === 0) {
      if (status) status.textContent = "no inputs";
      return;
    }
    var pluginRaw = (document.getElementById("scan-plugin") || {}).value || "";
    var dpRaw = (document.getElementById("scan-default-port") || {}).value || "0";
    var defaultPort = parseInt(dpRaw, 10);
    if (!isFinite(defaultPort) || defaultPort < 0) defaultPort = 0;
    var plugins = pluginRaw.split(",").map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
    var body = JSON.stringify({
      inputs: lines,
      plugins: plugins,
      default_port: defaultPort
    });
    if (status) status.textContent = "submitting " + lines.length + "…";
    fetch("/api/v1/scans/bulk", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: body,
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      var d = (res && res.data) || {};
      var ok = (d.submitted || []).length;
      var bad = (d.errors || []).length;
      if (status) status.textContent = "queued " + ok + ", failed " + bad;
      // Clear textarea on full success so a follow-up batch
      // starts clean. Leave it on partial-failure so the
      // operator can edit + resubmit.
      if (bad === 0) {
        ta.value = "";
      }
      renderScans();
    }).catch(function (e) {
      if (status) status.textContent = "error: " + e.message;
    });
  }

  // ---- v1.72: scheduled-scans panel (CRUD + toggles) ----

  // Polling cadence for the schedules table. Schedules
  // change rarely (operator-driven); a 30s tick is plenty
  // and doesn't hammer the API.
  var schedulesPollTimer = null;
  function scheduleSchedulesPoll(delayMs) {
    if (schedulesPollTimer) clearTimeout(schedulesPollTimer);
    schedulesPollTimer = setTimeout(renderSchedules, delayMs);
  }
  function renderSchedules() {
    fetch("/api/v1/schedules", {credentials: "same-origin"})
      .then(function (r) {
        if (r.status === 503) {
          return Promise.reject(new Error("scan orchestration disabled (start serve with --scan-store=memory or =db)"));
        }
        if (!r.ok) {
          return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
        }
        return r.json();
      })
      .then(function (res) {
        var rows = (res && res.data) || [];
        var body = document.getElementById("schedules-body");
        if (!body) return;
        if (rows.length === 0) {
          body.innerHTML = '<tr class="empty"><td colspan="8">no schedules — create one above</td></tr>';
          scheduleSchedulesPoll(30000);
          return;
        }
        body.innerHTML = rows.map(function (s) {
          var plugins = (s.template && s.template.plugins || []).join(",") || "—";
          // v1.73: cron-based schedules show the raw cron
          // expression in the Interval column rather than a
          // human duration. v1.75: append the timezone if
          // non-empty so operators see "0 9 * * 1-5
          // (America/New_York)" at a glance.
          var intervalDisplay;
          if (s.cron_expr) {
            intervalDisplay = "cron: " + s.cron_expr;
            if (s.timezone) {
              intervalDisplay += " (" + s.timezone + ")";
            }
          } else {
            intervalDisplay = humanInterval(s.interval_seconds);
          }
          var stateLabel = s.enabled ? "enabled" : "disabled";
          var lastFired = s.last_fired_at ? new Date(s.last_fired_at).toLocaleString() : "never";
          // v1.77: server-side computed next_fire_at. Empty
          // (zero time → omitempty drops the field) means the
          // schedule won't fire (disabled / invalid cron).
          // For schedules that ARE enabled, render the local-
          // clock string + a "(overdue)" suffix when the
          // predicted fire is already in the past — operators
          // see at a glance which schedules will trigger on
          // the next tick.
          var nextFire = "—";
          if (s.next_fire_at) {
            var nextDate = new Date(s.next_fire_at);
            nextFire = nextDate.toLocaleString();
            if (nextDate.getTime() < Date.now()) {
              nextFire += " (overdue)";
            }
          }
          var toggleLabel = s.enabled ? "Disable" : "Enable";
          var toggleAction = s.enabled ? "disable" : "enable";
          // v1.85: per-row "History" button opens the audit
          // view for this schedule. 503 (audit nil) surfaces
          // "audit unavailable" inside the panel — the button
          // is always rendered so memory-mode operators see a
          // consistent UI.
          var action =
            '<button type="button" data-sched-id="' + escAttr(s.id) +
            '" onclick="beginEditSchedule(this.dataset.schedId)">Edit</button>' +
            ' <button type="button" data-sched-id="' + escAttr(s.id) +
            '" data-sched-action="' + toggleAction +
            '" onclick="toggleSchedule(this.dataset.schedId, this.dataset.schedAction)">' +
            toggleLabel + '</button>' +
            ' <button type="button" data-sched-id="' + escAttr(s.id) +
            '" data-sched-name="' + escAttr(s.name || s.id) +
            '" onclick="openAuditView(this.dataset.schedId, this.dataset.schedName)">History</button>' +
            ' <button type="button" data-sched-id="' + escAttr(s.id) +
            '" data-sched-name="' + escAttr(s.name || s.id) +
            '" onclick="openRunsView(this.dataset.schedId, this.dataset.schedName)">Runs</button>' +
            ' <button type="button" data-sched-id="' + escAttr(s.id) +
            '" onclick="cloneSchedule(this.dataset.schedId)">Clone</button>' +
            ' <button type="button" data-sched-id="' + escAttr(s.id) +
            '" onclick="deleteSchedule(this.dataset.schedId)">Delete</button>';
          return '<tr data-sched-id="' + escAttr(s.id) + '">' +
            '<td>' + escText(s.name || "") + '</td>' +
            '<td><code>' + escText((s.template && s.template.input) || "") + '</code></td>' +
            '<td><code>' + escText(plugins) + '</code></td>' +
            '<td>' + escText(intervalDisplay) + '</td>' +
            '<td><code class="state-' + escAttr(stateLabel) + '">' + escText(stateLabel) + '</code></td>' +
            '<td>' + escText(lastFired) + '</td>' +
            '<td class="next-fire">' + escText(nextFire) + '</td>' +
            '<td>' + action + '</td>' +
            '</tr>';
        }).join("");
        scheduleSchedulesPoll(30000);
      })
      .catch(function (e) {
        var body = document.getElementById("schedules-body");
        if (body) body.innerHTML = '<tr class="empty"><td colspan="8">' + escText(e.message) + '</td></tr>';
        scheduleSchedulesPoll(60000);
      });
  }
  // humanInterval renders seconds as a human-friendly string.
  // 60 → "1m", 3600 → "1h", 86400 → "1d", and so on. Keeps
  // the table column narrow.
  function humanInterval(secs) {
    if (!secs) return "—";
    if (secs % 86400 === 0) return (secs / 86400) + "d";
    if (secs % 3600 === 0) return (secs / 3600) + "h";
    if (secs % 60 === 0) return (secs / 60) + "m";
    return secs + "s";
  }
  // v1.73: cadence-mode toggle. interval ↔ cron — only one
  // form field is visible + submitted. The backend rejects
  // both-set; the UI prevents that by hiding the inactive
  // input.
  function onScheduleCadenceModeChange() {
    var mode = (document.getElementById("schedule-cadence-mode") || {}).value || "interval";
    var intervalLabel = document.getElementById("schedule-interval-label");
    var cronLabel = document.getElementById("schedule-cron-label");
    var tzLabel = document.getElementById("schedule-timezone-label");
    if (intervalLabel && cronLabel) {
      if (mode === "cron") {
        intervalLabel.style.display = "none";
        cronLabel.style.display = "";
        if (tzLabel) tzLabel.style.display = "";
      } else {
        intervalLabel.style.display = "";
        cronLabel.style.display = "none";
        if (tzLabel) tzLabel.style.display = "none";
      }
    }
  }
  // v1.74: schedule edit-mode state. When editingScheduleID
  // is non-empty, submitSchedule sends PUT instead of POST.
  // beginEditSchedule populates the form + flips the button
  // labels; cancelEditSchedule resets back to create mode.
  //
  // v1.78: editingScheduleUpdatedAt carries the schedule's
  // updated_at value at edit-load time. submitSchedule sends
  // it as the If-Match header so concurrent edits surface as
  // 412 instead of silently overwriting.
  var editingScheduleID = "";
  var editingScheduleUpdatedAt = "";
  function beginEditSchedule(id) {
    if (!id) return;
    fetch("/api/v1/schedules/" + encodeURIComponent(id), {
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      var s = (res && res.data) || {};
      var nameEl = document.getElementById("schedule-name");
      var inputEl = document.getElementById("schedule-input");
      var pluginEl = document.getElementById("schedule-plugin");
      var modeEl = document.getElementById("schedule-cadence-mode");
      var intervalEl = document.getElementById("schedule-interval");
      var cronEl = document.getElementById("schedule-cron");
      var submitBtn = document.getElementById("schedule-submit-button");
      var cancelBtn = document.getElementById("schedule-cancel-button");
      var status = document.getElementById("schedule-submit-status");
      if (nameEl) nameEl.value = s.name || "";
      if (inputEl) inputEl.value = (s.template && s.template.input) || "";
      if (pluginEl) pluginEl.value = (s.template && s.template.plugins || []).join(",");
      if (modeEl) {
        modeEl.value = s.cron_expr ? "cron" : "interval";
        onScheduleCadenceModeChange();
      }
      if (intervalEl) intervalEl.value = s.interval_seconds || 3600;
      if (cronEl) cronEl.value = s.cron_expr || "";
      var tzEl = document.getElementById("schedule-timezone");
      if (tzEl) tzEl.value = s.timezone || "";
      // v1.89: load audit retention override into the form
      // so Update can round-trip the value (otherwise the
      // submit would zero it out by accident).
      var auditEl = document.getElementById("schedule-audit-retention-days");
      if (auditEl) auditEl.value = (s.audit_retention_days != null ? s.audit_retention_days : 0);
      if (submitBtn) submitBtn.textContent = "Update";
      if (cancelBtn) cancelBtn.style.display = "";
      if (status) status.textContent = "editing " + (s.id || "").slice(0, 8) + "…";
      editingScheduleID = s.id || "";
      // v1.78: capture updated_at for the optimistic-locking
      // precondition. Empty string means "skip" (e.g. server
      // didn't send it — back-compat).
      editingScheduleUpdatedAt = s.updated_at || "";
      // Scroll the form into view + focus the name field so
      // the operator can immediately start editing.
      if (nameEl) {
        nameEl.scrollIntoView({block: "center"});
        nameEl.focus();
      }
    }).catch(function (e) {
      var status = document.getElementById("schedule-submit-status");
      if (status) status.textContent = "edit-load failed: " + e.message;
    });
  }
  function cancelEditSchedule() {
    editingScheduleID = "";
    editingScheduleUpdatedAt = "";
    var submitBtn = document.getElementById("schedule-submit-button");
    var cancelBtn = document.getElementById("schedule-cancel-button");
    var status = document.getElementById("schedule-submit-status");
    if (submitBtn) submitBtn.textContent = "Create";
    if (cancelBtn) cancelBtn.style.display = "none";
    if (status) status.textContent = "";
    // Clear form fields so the operator can paste a fresh
    // create entry without leftover values.
    ["schedule-name", "schedule-input", "schedule-plugin", "schedule-cron", "schedule-timezone"].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.value = "";
    });
    var intervalEl = document.getElementById("schedule-interval");
    if (intervalEl) intervalEl.value = 3600;
    // v1.89: reset the audit retention override to 0 (inherit).
    var auditEl = document.getElementById("schedule-audit-retention-days");
    if (auditEl) auditEl.value = 0;
    var modeEl = document.getElementById("schedule-cadence-mode");
    if (modeEl) {
      modeEl.value = "interval";
      onScheduleCadenceModeChange();
    }
  }
  function submitSchedule(ev) {
    if (ev) ev.preventDefault();
    var name = (document.getElementById("schedule-name") || {}).value || "";
    var input = (document.getElementById("schedule-input") || {}).value || "";
    var pluginRaw = (document.getElementById("schedule-plugin") || {}).value || "";
    var mode = (document.getElementById("schedule-cadence-mode") || {}).value || "interval";
    var status = document.getElementById("schedule-submit-status");
    var plugins = pluginRaw.split(",").map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
    var payload = {
      name: name,
      template: { input: input, plugins: plugins }
    };
    if (mode === "cron") {
      var cron = (document.getElementById("schedule-cron") || {}).value || "";
      cron = cron.trim();
      if (!cron) {
        if (status) status.textContent = "cron expression required";
        return false;
      }
      payload.cron_expr = cron;
      // v1.75: optional timezone for cron schedules. Empty
      // means UTC (back-compat with v1.73/v1.74).
      var tz = (document.getElementById("schedule-timezone") || {}).value || "";
      tz = tz.trim();
      if (tz) {
        payload.timezone = tz;
      }
    } else {
      var intervalRaw = (document.getElementById("schedule-interval") || {}).value || "3600";
      var interval = parseInt(intervalRaw, 10);
      if (!isFinite(interval) || interval < 60) interval = 60;
      if (interval > 604800) interval = 604800;
      payload.interval_seconds = interval;
    }
    // v1.89: per-schedule audit retention override. 0 = inherit
    // global. Negative is rejected server-side; the UI clamps.
    var auditDaysRaw = (document.getElementById("schedule-audit-retention-days") || {}).value || "0";
    var auditDays = parseInt(auditDaysRaw, 10);
    if (!isFinite(auditDays) || auditDays < 0) auditDays = 0;
    if (auditDays > 3650) auditDays = 3650;
    if (auditDays > 0) {
      payload.audit_retention_days = auditDays;
    }
    var body = JSON.stringify(payload);
    var isUpdate = editingScheduleID !== "";
    var url = isUpdate
      ? "/api/v1/schedules/" + encodeURIComponent(editingScheduleID)
      : "/api/v1/schedules";
    var method = isUpdate ? "PUT" : "POST";
    if (status) status.textContent = isUpdate ? "updating…" : "creating…";
    // v1.78: send the optimistic-locking precondition on
    // PUT. The server compares it against stored updated_at
    // and returns 412 on mismatch.
    var headers = {"Content-Type": "application/json"};
    if (isUpdate && editingScheduleUpdatedAt) {
      headers["If-Match"] = editingScheduleUpdatedAt;
    }
    // v1.81: capture the payload so the 412 merge-view can
    // diff our pending values against the server's fresh
    // state and offer Accept Server / Force Overwrite.
    pendingMergePayload = payload;
    fetch(url, {
      method: method,
      headers: headers,
      body: body,
      credentials: "same-origin"
    }).then(function (r) {
      if (r.status === 412) {
        // v1.81: open the merge-view instead of throwing.
        return r.text().then(function () {
          enterMergeView(editingScheduleID);
          return null;
        });
      }
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      if (res === null) return; // 412 → merge view took over.
      var s = (res && res.data) || {};
      if (status) {
        status.textContent = (isUpdate ? "updated · " : "created · ") + (s.id || "").slice(0, 8);
      }
      // After update, leave edit mode + clear; after create,
      // just clear name + input (keep plugin / interval to
      // ease the next entry).
      if (isUpdate) {
        cancelEditSchedule();
      } else {
        var nameEl = document.getElementById("schedule-name");
        var inputEl = document.getElementById("schedule-input");
        if (nameEl) nameEl.value = "";
        if (inputEl) inputEl.value = "";
      }
      renderSchedules();
    }).catch(function (e) {
      if (status) status.textContent = "error: " + e.message;
    });
    return false;
  }
  // v1.81: merge-view state. pendingMergePayload is the
  // operator's last submitted body — captured at submit time
  // so we can both diff it against the freshly-fetched
  // server state AND re-submit it (without If-Match) if the
  // operator chooses Force Overwrite.
  var pendingMergePayload = null;
  function enterMergeView(id) {
    var mergeView = document.getElementById("schedule-merge-view");
    var status = document.getElementById("schedule-submit-status");
    if (status) status.textContent = "concurrent edit detected — see merge view";
    if (!mergeView) return;
    // Fetch the fresh server state to diff against.
    fetch("/api/v1/schedules/" + encodeURIComponent(id), {
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      var server = (res && res.data) || {};
      // Update the cached updated_at to the fresh value so
      // Accept Server lands on the latest stamp.
      editingScheduleUpdatedAt = server.updated_at || "";
      window.scheduleMergeServer = server;
      var diff = computeScheduleDiff(pendingMergePayload || {}, server);
      var list = document.getElementById("schedule-merge-diff");
      if (list) {
        if (!diff.length) {
          list.innerHTML = '<li>(no field-level diffs — likely a race on updated_at alone)</li>';
        } else {
          // v1.83: each row has radio buttons for per-field
          // cherry-pick. Default selection is "mine" (the
          // operator's edits) — matches v1.81 Force-overwrite
          // semantics if the operator just clicks Apply.
          list.innerHTML = diff.map(function (d, i) {
            var rowName = "merge-row-" + i;
            return '<li data-field="' + escAttr(d.field) + '">' +
              '<code>' + escText(d.field) + '</code>: ' +
              '<label><input type="radio" name="' + rowName + '" value="mine" checked> mine=<code>' + escText(d.mine) + '</code></label> · ' +
              '<label style="margin-left: 0.5em;"><input type="radio" name="' + rowName + '" value="server"> server=<code>' + escText(d.server) + '</code></label>' +
              '</li>';
          }).join("");
        }
      }
      mergeView.style.display = "";
    }).catch(function (e) {
      if (status) status.textContent = "merge-view fetch failed: " + e.message;
    });
  }
  // computeScheduleDiff (v1.81) compares the operator's
  // pending payload to the server's fresh state, returning
  // [{field, mine, server}] for each visible difference.
  // Empty result means the only conflict was on
  // updated_at — common when a concurrent SetEnabled raced
  // the operator's edit (SetEnabled doesn't bump updated_at
  // in v1.78+ but other "soft" writes might in the future).
  function computeScheduleDiff(mine, server) {
    var out = [];
    function strify(v) {
      if (v === null || v === undefined) return "—";
      if (Array.isArray(v)) return v.join(",");
      return String(v);
    }
    function pushIf(field, m, s) {
      if (strify(m) !== strify(s)) {
        out.push({field: field, mine: strify(m), server: strify(s)});
      }
    }
    pushIf("name", mine.name, server.name);
    pushIf("template.input", (mine.template || {}).input, (server.template || {}).input);
    pushIf("template.plugins", (mine.template || {}).plugins, (server.template || {}).plugins);
    pushIf("interval_seconds", mine.interval_seconds, server.interval_seconds);
    pushIf("cron_expr", mine.cron_expr, server.cron_expr);
    pushIf("timezone", mine.timezone, server.timezone);
    return out;
  }
  // acceptServerSchedule (v1.81): discard the operator's
  // pending edits, re-load the form with the freshly-fetched
  // server state, and close the merge view. The operator can
  // then edit again from a clean baseline.
  function acceptServerSchedule() {
    var server = window.scheduleMergeServer;
    var mergeView = document.getElementById("schedule-merge-view");
    if (!server) return;
    // Re-populate the form via the same beginEditSchedule
    // path so cadence-mode toggle + tz field + edit-mode
    // labels stay consistent.
    beginEditSchedule(server.id);
    if (mergeView) mergeView.style.display = "none";
    pendingMergePayload = null;
    window.scheduleMergeServer = null;
  }
  // forceOverwriteSchedule (v1.81): re-submit the operator's
  // pending payload WITHOUT If-Match — last-write-wins. Used
  // when the operator has reviewed the diff and decided
  // their version should prevail.
  function forceOverwriteSchedule() {
    var mergeView = document.getElementById("schedule-merge-view");
    var status = document.getElementById("schedule-submit-status");
    if (!pendingMergePayload || !editingScheduleID) return;
    if (!confirm("Force-overwrite the server's version of this schedule with your edits? This cannot be undone. The override will be recorded in the schedule's audit log.")) return;
    if (status) status.textContent = "force-overwriting…";
    fetch("/api/v1/schedules/" + encodeURIComponent(editingScheduleID), {
      method: "PUT",
      // v1.78: no If-Match → server skips the precondition.
      // v1.84: explicit force-overwrite marker so the
      // handler persists a before/after audit snapshot.
      headers: {
        "Content-Type": "application/json",
        "X-Schedule-Force-Overwrite": "true"
      },
      credentials: "same-origin",
      body: JSON.stringify(pendingMergePayload)
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function () {
      if (mergeView) mergeView.style.display = "none";
      pendingMergePayload = null;
      window.scheduleMergeServer = null;
      cancelEditSchedule();
      renderSchedules();
    }).catch(function (e) {
      if (status) status.textContent = "force overwrite failed: " + e.message;
    });
  }
  // applySelectedMerge (v1.83): builds a merged payload from
  // the per-field radio selections in the merge view + PUTs
  // with the freshly-fetched If-Match. A concurrent third
  // operator who raced between enterMergeView and this call
  // re-opens the merge flow (412 → enterMergeView again).
  function applySelectedMerge() {
    var server = window.scheduleMergeServer;
    var mergeView = document.getElementById("schedule-merge-view");
    var list = document.getElementById("schedule-merge-diff");
    var status = document.getElementById("schedule-submit-status");
    if (!server || !pendingMergePayload || !editingScheduleID || !list) return;
    // Start from a deep-ish copy of the operator's pending
    // payload (only fields that map to schedule columns
    // matter; nested objects we touch: template).
    var merged = {
      name: pendingMergePayload.name,
      template: {
        input: (pendingMergePayload.template || {}).input,
        plugins: (pendingMergePayload.template || {}).plugins,
        default_port: (pendingMergePayload.template || {}).default_port
      },
      interval_seconds: pendingMergePayload.interval_seconds,
      cron_expr: pendingMergePayload.cron_expr,
      timezone: pendingMergePayload.timezone
    };
    // Walk each diff row + apply the operator's selection.
    var rows = list.querySelectorAll("li[data-field]");
    for (var i = 0; i < rows.length; i++) {
      var field = rows[i].getAttribute("data-field");
      var checked = rows[i].querySelector('input[type="radio"]:checked');
      if (!checked || checked.value !== "server") continue;
      // Operator picked server for this field — copy from
      // server.
      applyServerField(merged, field, server);
    }
    if (status) status.textContent = "applying merge…";
    var headers = {"Content-Type": "application/json"};
    if (editingScheduleUpdatedAt) {
      // v1.83: still send If-Match — a third concurrent
      // edit re-opens the merge flow.
      headers["If-Match"] = editingScheduleUpdatedAt;
    }
    // Re-capture so a subsequent 412 has the right payload.
    pendingMergePayload = merged;
    fetch("/api/v1/schedules/" + encodeURIComponent(editingScheduleID), {
      method: "PUT",
      headers: headers,
      credentials: "same-origin",
      body: JSON.stringify(merged)
    }).then(function (r) {
      if (r.status === 412) {
        return r.text().then(function () {
          enterMergeView(editingScheduleID);
          return null;
        });
      }
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      if (res === null) return; // 412 → merge view re-opened.
      if (mergeView) mergeView.style.display = "none";
      pendingMergePayload = null;
      window.scheduleMergeServer = null;
      cancelEditSchedule();
      renderSchedules();
    }).catch(function (e) {
      if (status) status.textContent = "apply merge failed: " + e.message;
    });
  }
  // applyServerField copies a single named field from
  // server into the merged payload. Handles the
  // template.<x> nested keys explicitly because the dot
  // notation isn't auto-resolvable in plain JS.
  function applyServerField(merged, field, server) {
    switch (field) {
      case "name":
        merged.name = server.name;
        break;
      case "template.input":
        merged.template.input = (server.template || {}).input;
        break;
      case "template.plugins":
        merged.template.plugins = (server.template || {}).plugins;
        break;
      case "interval_seconds":
        merged.interval_seconds = server.interval_seconds;
        // If picking server interval, drop cron — cadence
        // XOR must hold.
        if (server.interval_seconds) merged.cron_expr = "";
        break;
      case "cron_expr":
        merged.cron_expr = server.cron_expr;
        if (server.cron_expr) merged.interval_seconds = 0;
        break;
      case "timezone":
        merged.timezone = server.timezone;
        break;
    }
  }
  // openAuditView (v1.85) fetches /api/v1/schedules/{id}/audit
  // + renders the events as a table. Each row shows
  // occurred_at, operator, event_type, and the field-level
  // diff between payload_before and payload_after.
  //
  // 503 (audit store nil) surfaces "audit log unavailable"
  // inside the panel — the button is always rendered so
  // memory-mode operators see a consistent UI.
  function openAuditView(id, displayName) {
    var view = document.getElementById("schedule-audit-view");
    var body = document.getElementById("schedule-audit-body");
    var subtitle = document.getElementById("schedule-audit-subtitle");
    if (!view || !body) return;
    if (subtitle) {
      subtitle.textContent = displayName ? (displayName + " · " + id) : id;
    }
    body.innerHTML = '<tr class="empty"><td colspan="4">loading…</td></tr>';
    view.style.display = "";
    view.scrollIntoView({block: "nearest"});
    fetch("/api/v1/schedules/" + encodeURIComponent(id) + "/audit", {
      credentials: "same-origin"
    }).then(function (r) {
      if (r.status === 503) {
        body.innerHTML = '<tr class="empty"><td colspan="4">audit log unavailable — run with --scan-store=db to enable</td></tr>';
        return null;
      }
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      if (res === null) return;
      var events = (res && res.data) || [];
      if (!events.length) {
        body.innerHTML = '<tr class="empty"><td colspan="4">no audit events recorded for this schedule</td></tr>';
        return;
      }
      body.innerHTML = events.map(function (e) {
        var when = e.occurred_at ? new Date(e.occurred_at).toLocaleString() : "—";
        // v1.89: dedicated "Deleted" badge for event_type='delete'.
        // The v1.88 audit event captures the pre-delete state in
        // payload_before; payload_after is JSON null. Rendering
        // every field as "X → —" works but obscures the actual
        // operator intent. Show a red "Deleted" badge + the
        // pre-delete name/input so operators recognise the row
        // at a glance.
        var diffHTML;
        var eventBadgeHTML;
        if (e.event_type === "delete") {
          eventBadgeHTML = '<span style="background:#c33;color:#fff;padding:0.1em 0.5em;border-radius:0.3em;font-weight:bold;">DELETED</span>';
          var preDelete = (function () {
            if (e.payload_before == null) return null;
            if (typeof e.payload_before === "string") {
              try { return JSON.parse(e.payload_before); } catch (_) { return null; }
            }
            return e.payload_before;
          })();
          if (preDelete) {
            diffHTML = '<span class="sub">pre-delete snapshot:</span> ' +
              '<code>' + escText(preDelete.name || "—") + '</code>' +
              ' / input=<code>' + escText((preDelete.template || {}).input || "—") + '</code>';
          } else {
            diffHTML = '<span class="sub">(no pre-delete snapshot)</span>';
          }
        } else {
          eventBadgeHTML = '<code>' + escText(e.event_type || "—") + '</code>';
          var diff = computeAuditEventDiff(e);
          if (!diff.length) {
            diffHTML = '<span class="sub">(no field-level changes)</span>';
          } else {
            diffHTML = '<ul class="audit-diff" style="margin: 0; padding-left: 1em;">' +
              diff.map(function (d) {
                return '<li><code>' + escText(d.field) + '</code>: <code>' +
                  escText(d.before) + '</code> → <code>' + escText(d.after) + '</code></li>';
              }).join("") + '</ul>';
          }
        }
        return '<tr>' +
          '<td>' + escText(when) + '</td>' +
          '<td>' + escText(e.operator || "—") + '</td>' +
          '<td>' + eventBadgeHTML + '</td>' +
          '<td>' + diffHTML + '</td>' +
          '</tr>';
      }).join("");
    }).catch(function (err) {
      body.innerHTML = '<tr class="empty"><td colspan="4">audit fetch failed: ' + escText(err.message) + '</td></tr>';
    });
  }
  function closeAuditView() {
    var view = document.getElementById("schedule-audit-view");
    if (view) view.style.display = "none";
  }
  // openRunsView (v1.92) fetches /api/v1/schedules/{id}/runs +
  // renders the jobs as a table. Newest-first by created_at.
  // 503 (scan store nil) surfaces an "unavailable" message
  // inside the panel — the button is always rendered for UI
  // consistency.
  function openRunsView(id, displayName) {
    var view = document.getElementById("schedule-runs-view");
    var body = document.getElementById("schedule-runs-body");
    var subtitle = document.getElementById("schedule-runs-subtitle");
    if (!view || !body) return;
    if (subtitle) {
      subtitle.textContent = displayName ? (displayName + " · " + id) : id;
    }
    body.innerHTML = '<tr class="empty"><td colspan="5">loading…</td></tr>';
    view.style.display = "";
    view.scrollIntoView({block: "nearest"});
    fetch("/api/v1/schedules/" + encodeURIComponent(id) + "/runs", {
      credentials: "same-origin"
    }).then(function (r) {
      if (r.status === 503) {
        body.innerHTML = '<tr class="empty"><td colspan="5">scan store unavailable — run with --scan-store=db to enable persistence</td></tr>';
        return null;
      }
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      if (res === null) return;
      var jobs = (res && res.data) || [];
      if (!jobs.length) {
        body.innerHTML = '<tr class="empty"><td colspan="5">no runs recorded for this schedule yet</td></tr>';
        return;
      }
      body.innerHTML = jobs.map(function (j) {
        var when = j.created_at ? new Date(j.created_at).toLocaleString() : "—";
        var state = j.state || "—";
        var findings = (j.stats && j.stats.findings_count) || 0;
        var targets = (j.stats && (j.stats.targets_scanned || 0) + "/" + (j.stats.targets_seen || 0)) || "0/0";
        return '<tr>' +
          '<td>' + escText(when) + '</td>' +
          '<td><code class="state-' + escAttr(state) + '">' + escText(state) + '</code></td>' +
          '<td><code>' + escText(j.id || "—") + '</code></td>' +
          '<td>' + escText(String(findings)) + '</td>' +
          '<td>' + escText(targets) + '</td>' +
          '</tr>';
      }).join("");
    }).catch(function (err) {
      body.innerHTML = '<tr class="empty"><td colspan="5">runs fetch failed: ' + escText(err.message) + '</td></tr>';
    });
  }
  function closeRunsView() {
    var view = document.getElementById("schedule-runs-view");
    if (view) view.style.display = "none";
  }
  // computeAuditEventDiff: parse payload_before + payload_after
  // and produce a list of {field, before, after} for each
  // editable field that changed. Reuses the v1.81 strify
  // semantics (arrays joined on "," / null/undefined → "—").
  function computeAuditEventDiff(ev) {
    function parse(raw) {
      if (raw == null) return {};
      if (typeof raw === "string") {
        try { return JSON.parse(raw); } catch (e) { return {}; }
      }
      return raw;
    }
    var before = parse(ev.payload_before);
    var after = parse(ev.payload_after);
    function strify(v) {
      if (v === null || v === undefined) return "—";
      if (Array.isArray(v)) return v.join(",");
      return String(v);
    }
    var out = [];
    function pushIf(field, b, a) {
      if (strify(b) !== strify(a)) {
        out.push({field: field, before: strify(b), after: strify(a)});
      }
    }
    pushIf("name", before.name, after.name);
    pushIf("template.input", (before.template || {}).input, (after.template || {}).input);
    pushIf("template.plugins", (before.template || {}).plugins, (after.template || {}).plugins);
    pushIf("interval_seconds", before.interval_seconds, after.interval_seconds);
    pushIf("cron_expr", before.cron_expr, after.cron_expr);
    pushIf("timezone", before.timezone, after.timezone);
    pushIf("enabled", before.enabled, after.enabled);
    return out;
  }
  // previewNextFire (v1.77) sends the current form values to
  // POST /api/v1/schedules/preview and renders the response
  // below the submit row. Re-uses the same field readers as
  // submitSchedule so cadence-mode toggle + timezone all
  // round-trip. Errors surface inline (e.g. "invalid cron
  // expression: …") so the operator can fix the form before
  // submitting.
  //
  // v1.82: in-flight requests are cancelled via
  // AbortController whenever a newer previewNextFire fires.
  // This prevents stale responses from flashing the wrong
  // value during fast typing (the v1.80 debounce delays the
  // dispatch but doesn't cancel an already-dispatched fetch).
  var previewAbortController = null;
  function previewNextFire() {
    var preview = document.getElementById("schedule-next-fire-preview");
    if (!preview) return;
    var name = (document.getElementById("schedule-name") || {}).value || "preview";
    var input = (document.getElementById("schedule-input") || {}).value || "";
    var plugin = (document.getElementById("schedule-plugin") || {}).value || "";
    var mode = (document.getElementById("schedule-cadence-mode") || {}).value || "interval";
    var payload = {
      name: name,
      template: { input: input, plugins: plugin ? plugin.split(",").map(function (p) { return p.trim(); }).filter(Boolean) : undefined }
    };
    if (mode === "cron") {
      var cron = ((document.getElementById("schedule-cron") || {}).value || "").trim();
      if (!cron) {
        preview.textContent = "preview: enter a cron expression first";
        return;
      }
      payload.cron_expr = cron;
      var tz = ((document.getElementById("schedule-timezone") || {}).value || "").trim();
      if (tz) payload.timezone = tz;
    } else {
      var intervalRaw = (document.getElementById("schedule-interval") || {}).value || "3600";
      var interval = parseInt(intervalRaw, 10);
      if (!interval || interval < 60) {
        preview.textContent = "preview: interval must be ≥ 60s";
        return;
      }
      payload.interval_seconds = interval;
    }
    preview.textContent = "preview: …";
    // v1.79: request 5 fires for the cron mode (operators
    // sanity-check the pattern), 1 for interval (next fire
    // is enough; subsequent fires are trivially derivable).
    var count = mode === "cron" ? 5 : 1;
    // v1.82: cancel the in-flight preview (if any) before
    // dispatching a new one. AbortController.abort() is a
    // no-op when the previous request already completed.
    if (previewAbortController) {
      try { previewAbortController.abort(); } catch (_) { /* ignore */ }
    }
    previewAbortController = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var signal = previewAbortController ? previewAbortController.signal : undefined;
    fetch("/api/v1/schedules/preview?count=" + count, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
      signal: signal
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      var d = (res && res.data) || {};
      var fires = d.next_fires || (d.next_fire_at ? [d.next_fire_at] : []);
      if (!fires.length) {
        preview.textContent = "preview: schedule won't fire";
        return;
      }
      var tzSuffix = d.timezone ? " (" + d.timezone + ")" : "";
      if (fires.length === 1) {
        var when = new Date(fires[0]);
        var label = "next fire: " + when.toLocaleString() + tzSuffix;
        if (when.getTime() < Date.now()) {
          label += " — overdue (will fire on next tick)";
        }
        preview.textContent = label;
        return;
      }
      // Multi-fire view (cron mode). Render as a small list
      // so the operator can sanity-check the pattern.
      var html = 'next ' + fires.length + ' fires' + escText(tzSuffix) + ':<ol class="next-fires-list">';
      for (var i = 0; i < fires.length; i++) {
        var w = new Date(fires[i]);
        var line = w.toLocaleString();
        if (w.getTime() < Date.now()) {
          line += " — overdue";
        }
        html += '<li>' + escText(line) + '</li>';
      }
      html += '</ol>';
      preview.innerHTML = html;
    }).catch(function (e) {
      // v1.82: AbortError is expected when a newer call
      // cancels this one. Stay silent — the newer fetch's
      // result will overwrite the panel.
      if (e && (e.name === "AbortError" || (e.message || "").indexOf("abort") !== -1)) return;
      preview.textContent = "preview error: " + e.message;
    });
  }
  function toggleSchedule(id, action) {
    if (!id || (action !== "enable" && action !== "disable")) return;
    fetch("/api/v1/schedules/" + encodeURIComponent(id) + "/" + action, {
      method: "POST",
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      renderSchedules();
    }).catch(function (e) {
      var body = document.getElementById("schedules-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="8">toggle failed: ' + escText(e.message) + '</td></tr>';
    });
  }
  function deleteSchedule(id) {
    if (!id) return;
    if (!confirm("Delete schedule? This cannot be undone.")) return;
    fetch("/api/v1/schedules/" + encodeURIComponent(id), {
      method: "DELETE",
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok && r.status !== 204) {
        return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      }
      renderSchedules();
    }).catch(function (e) {
      var body = document.getElementById("schedules-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="8">delete failed: ' + escText(e.message) + '</td></tr>';
    });
  }
  // bulkScheduleEnable (v1.95) POSTs to
  // /schedules/bulk/{enable|disable}. Shows the affected count
  // in the status line + re-renders the table.
  function bulkScheduleEnable(enabled) {
    var label = enabled ? "Resume All" : "Pause All";
    var action = enabled ? "enable" : "disable";
    if (!confirm(label + ": apply to every schedule? Audit log records each state change.")) return;
    var status = document.getElementById("schedule-bulk-status");
    if (status) status.textContent = label + "…";
    fetch("/api/v1/schedules/bulk/" + action, {
      method: "POST",
      credentials: "same-origin"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function (res) {
      var d = (res && res.data) || {};
      var n = (d.affected != null) ? d.affected : "?";
      var fa = d.failed_audits || 0;
      if (status) {
        var msg = label + " done — " + n + " schedule(s) flipped";
        if (fa > 0) msg += " (" + fa + " audit row(s) failed)";
        status.textContent = msg;
      }
      renderSchedules();
    }).catch(function (e) {
      if (status) status.textContent = "bulk op failed: " + e.message;
    });
  }
  // cloneSchedule (v1.93) POSTs to /schedules/{id}/clone with
  // empty body. Server defaults the name to "<source> (copy)";
  // operator can rename via the Edit button on the cloned row
  // immediately after. Adds the cloned schedule + re-renders
  // the table so the new row appears.
  function cloneSchedule(id) {
    if (!id) return;
    fetch("/api/v1/schedules/" + encodeURIComponent(id) + "/clone", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "same-origin",
      body: "{}"
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (t) { throw new Error("HTTP " + r.status + ": " + t); });
      return r.json();
    }).then(function () {
      renderSchedules();
    }).catch(function (e) {
      var body = document.getElementById("schedules-body");
      if (body) body.innerHTML = '<tr class="empty"><td colspan="8">clone failed: ' + escText(e.message) + '</td></tr>';
    });
  }

  // Expose cancelScan + submitScan + bulk helpers as page
  // globals so the inline onclick + onsubmit handlers find them.
  window.cancelScan = cancelScan;
  window.submitScan = submitScan;
  window.toggleBulkPanel = toggleBulkPanel;
  window.bulkSubmitScan = bulkSubmitScan;
  // v1.72 schedule helpers.
  window.submitSchedule = submitSchedule;
  window.toggleSchedule = toggleSchedule;
  window.deleteSchedule = deleteSchedule;
  // v1.93 schedule clone.
  window.cloneSchedule = cloneSchedule;
  // v1.95 bulk pause/resume.
  window.bulkScheduleEnable = bulkScheduleEnable;
  // v1.73 cadence mode toggle.
  window.onScheduleCadenceModeChange = onScheduleCadenceModeChange;
  // v1.74 schedule edit-mode helpers.
  window.beginEditSchedule = beginEditSchedule;
  window.cancelEditSchedule = cancelEditSchedule;
  // v1.77 next-fire preview.
  window.previewNextFire = previewNextFire;
  // v1.81 412 merge-view helpers.
  window.acceptServerSchedule = acceptServerSchedule;
  window.forceOverwriteSchedule = forceOverwriteSchedule;
  // v1.83 per-field cherry-pick.
  window.applySelectedMerge = applySelectedMerge;
  // v1.85 audit history view.
  window.openAuditView = openAuditView;
  window.closeAuditView = closeAuditView;
  // v1.92 run history view.
  window.openRunsView = openRunsView;
  window.closeRunsView = closeRunsView;

  // v1.68: load the plugin list once on page boot to populate
  // the scan-submit form's <datalist>. Best-effort: a 503
  // response (or any failure) leaves the datalist empty and
  // the operator types plugin names by hand. Plugin set is
  // build-time stable, so a single load suffices.
  function loadPluginDatalist() {
    var list = document.getElementById("scan-plugin-options");
    if (!list) return;
    fetch("/api/v1/plugins", {credentials: "same-origin"})
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (res) {
        var rows = (res && res.data) || [];
        if (!rows.length) return;
        // Sort by name + emit one <option> per plugin. The
        // option's value is the plugin name (what the operator
        // types); the data-port label is shown as the
        // dropdown's right-side annotation in modern browsers.
        rows.sort(function (a, b) {
          return (a.name || "").localeCompare(b.name || "");
        });
        list.innerHTML = rows.map(function (p) {
          var name = escAttr(p.name || "");
          var port = p.default_port ? " (port " + p.default_port + ")" : "";
          var label = escAttr((p.description || "") + port).slice(0, 80);
          return '<option value="' + name + '" label="' + label + '"></option>';
        }).join("");
      })
      .catch(function () { /* silent — empty datalist is OK */ });
  }
  loadPluginDatalist();

  // v1.80: live preview on cadence-field change. The
  // operator's input is debounced (350ms) so mid-typing
  // ("0 9 * * 1-" without the closing "5") doesn't fire a
  // burst of /preview calls. The cron path still surfaces
  // parse errors inline, but only after the operator
  // pauses typing.
  //
  // We attach to input + change (cadence-mode is a <select>
  // which fires change but not input). The manual "Preview
  // next fire" button (v1.77) remains as a force-refresh
  // shortcut.
  var previewDebounceTimer = null;
  function schedulePreviewRefresh() {
    if (previewDebounceTimer) clearTimeout(previewDebounceTimer);
    previewDebounceTimer = setTimeout(function () {
      previewNextFire();
      previewDebounceTimer = null;
    }, 350);
  }
  ["schedule-cadence-mode", "schedule-interval", "schedule-cron", "schedule-timezone"].forEach(function (id) {
    var el = document.getElementById(id);
    if (!el) return;
    el.addEventListener("input", schedulePreviewRefresh);
    el.addEventListener("change", schedulePreviewRefresh);
  });

  // Initial load.
  renderTriage(); renderFindings(); renderRuns(); refreshAudit(); renderReloadCadence();
  renderScans();
  renderSchedules();

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

  // v1.63: scan_state_change events from the orch broadcaster.
  // Re-render the scans table immediately on every transition so
  // the dashboard reflects state without waiting for the next
  // poll tick. The polling timer still runs as a safety net for
  // transitions the SSE stream missed (e.g., reconnect gap),
  // just at the slower 10s "idle" cadence — renderScans()
  // upgrades it back to 2s if it sees an active row.
  es.addEventListener("scan_state_change", function () {
    renderScans();
  });

  // v1.65: scan_stats_progress events deliver mid-run Stats
  // snapshots. We update the affected row's Targets/Findings
  // cell in place rather than re-rendering the whole table —
  // each event might fire 2/sec per running job and the table
  // re-render is much heavier than a single innerHTML swap.
  es.addEventListener("scan_stats_progress", function (ev) {
    try {
      var data = JSON.parse(ev.data);
      if (!data || !data.id) return;
      var row = document.querySelector('tr[data-scan-id="' + data.id + '"]');
      if (!row) return;
      var cell = row.querySelector('td[data-scan-stats]');
      if (!cell) return;
      var s = data.stats || {};
      var targets = (s.targets_scanned || 0) + " / " + (s.targets_seen || 0);
      var findings = s.findings_count || 0;
      cell.textContent = targets + "  ·  " + findings + " findings";
      // v1.66: refresh the per-plugin breakdown tooltip.
      var byPlugin = data.findings_by_plugin || {};
      var breakdown = Object.keys(byPlugin)
        .sort()
        .map(function (k) { return k + ": " + byPlugin[k]; })
        .join(", ");
      if (breakdown) {
        cell.setAttribute("title", breakdown);
      } else {
        cell.removeAttribute("title");
      }
    } catch (_) {
      // best-effort; fall back to next render
    }
  });
})();
</script>
</body>
</html>
`
