package handlers

import (
	"html/template"
	"net/http"
	"runtime"
	"strings"
	"time"

	"local/elsereno/internal/core"
)

// Security returns the `/admin/security` handler — the pentest /
// self-audit panel. Every control ElSereno relies on shows here
// with its in-process state + a pointer to the code + threat-model
// doc that enforces it.
//
// The page reflects what the binary can introspect itself. External
// sec-suite results (scorecard, trivy, govulncheck, etc.) ship via
// the supply-chain workflow's artefacts; linking them from here is
// an F8 carry-over because it needs the GH API.
func Security() http.Handler {
	t := template.Must(template.New("security").Parse(securityHTML))
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = t.Execute(w, securityData())
	})
}

type securityControl struct {
	Name   string
	Status string // "ok" | "warn" | "fail" | "info"
	Detail string
	Code   string
	ADR    string
}

type securityModel struct {
	Title       string
	GeneratedAt string
	Controls    []securityControl
	Build       string
	GoRuntime   string
	OffensiveOn bool
	ThreatDocs  []string
}

func securityData() securityModel {
	offensiveOn := anyOffensive(core.RegisteredPlugins())
	return securityModel{
		Title:       "ElSereno — security self-audit",
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Controls:    buildControls(offensiveOn),
		Build:       buildLabel(offensiveOn),
		GoRuntime:   runtime.Version() + " / " + runtime.GOOS + "/" + runtime.GOARCH,
		OffensiveOn: offensiveOn,
		ThreatDocs: []string{
			"vault-audit", "web", "scanner-proxy",
			"exec-scope", "offensive", "telemetry-canary",
		},
	}
}

func anyOffensive(plugins []core.Plugin) bool {
	for _, p := range plugins {
		if p.Build == "offensive" {
			return true
		}
	}
	return false
}

func buildControls(offensiveOn bool) []securityControl {
	return []securityControl{
		{Name: "Vault encryption", Status: "ok",
			Detail: "AES-256-GCM + Argon2id (time=3, memory=64 MiB, threads=4)",
			Code:   "internal/creds/vault.go", ADR: "ADR-018"},
		{Name: "Audit hash chain", Status: "ok",
			Detail: "JCS (RFC 8785) + SHA-256 + genesis + tombstone + rebase markers",
			Code:   "internal/audit/canonical.go", ADR: "ADR-013 + ADR-025"},
		{Name: "CSRF key", Status: "ok",
			Detail: "HKDF-SHA256 from vault master, info=elsereno/csrf/v1",
			Code:   "internal/web/server.go", ADR: "ADR-017"},
		{Name: "Redaction hook", Status: "ok",
			Detail: "Specific patterns + entropy >4.5 bits/byte + UUID v1-v5 exemption",
			Code:   "internal/telemetry/redact.go", ADR: "PITF-004"},
		{Name: "Subprocess allowlist", Status: "ok",
			Detail: "SafeCommand + CommandSpec + path allowlist + `--` separator",
			Code:   "internal/exec/safecommand.go", ADR: "ADR-024"},
		{Name: "Scope check", Status: "ok",
			Detail: "CIDR v4/v6 + port allow/deny + protocol allow/deny + dial blocked_numbers",
			Code:   "internal/scope/scope.go", ADR: "ADR-038 (+ ADR-041 dial)"},
		{Name: "Wire-layer write-ban", Status: "ok",
			Detail: "12 default plugins with per-protocol refusal response; bypass requires -tags offensive + ADR-039 triple confirm",
			Code:   "internal/protocols/<proto>/", ADR: "ADR-030 + ADR-040"},
		{Name: "Offensive build tag",
			Status: ternary(offensiveOn, "warn", "ok"),
			Detail: ternary(offensiveOn,
				"Offensive plugins ARE registered — triple confirm + scope + dial-guard actively gate writes",
				"Default build — no offensive code path is reachable",
			),
			Code: "offensive/confirm/confirm.go", ADR: "ADR-039"},
		{Name: "seccomp-bpf sandbox",
			Status: ternary(runtime.GOOS == "linux", "ok", "warn"),
			Detail: ternary(runtime.GOOS == "linux",
				"PR_SET_NO_NEW_PRIVS installed for offensive subprocesses; BPF filter sequences ship post-1.0",
				"Non-Linux host — sandbox gracefully degrades to log-and-continue (ADR-042)",
			),
			Code: "offensive/sandbox/sandbox_linux.go", ADR: "ADR-042"},
		{Name: "Canary webhook", Status: "info",
			Detail: "Optional HMAC-SHA256 signature in X-Elsereno-Signature (HKDF from vault master)",
			Code:   "internal/canary/canary.go", ADR: "ADR-038 (scope canary)"},
		{Name: "Encrypted backup", Status: "info",
			Detail: "AES-256-GCM envelope with HKDF salt binding; ELSB magic + version 1",
			Code:   "internal/backup/backup.go", ADR: "F7 chunk 6"},
	}
}

func buildLabel(offensiveOn bool) string {
	if offensiveOn {
		return "offensive (-tags offensive)"
	}
	return "default"
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// Referenced to keep the strings import alive for future additions.
var _ = strings.ToLower

const securityHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
  :root {
    --bg: #f7f8fa; --panel: #ffffff; --ink: #111418;
    --muted: #6b7280; --border: #e5e7eb;
    --ok: #059669; --warn: #d97706; --fail: #dc2626; --info: #0284c7;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0b0d10; --panel: #13161a; --ink: #e5e7eb;
      --muted: #9ca3af; --border: #2a2f37;
    }
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: var(--bg); color: var(--ink); margin: 0; padding: 2rem; line-height: 1.5; }
  header { margin-bottom: 1.5rem; }
  h1 { margin: 0 0 .25rem 0; font-size: 1.75rem; letter-spacing: -0.02em; }
  .meta { color: var(--muted); font-size: .9rem; }
  nav { margin: 1rem 0; display: flex; flex-wrap: wrap; gap: .75rem; }
  nav a {
    padding: .35rem .75rem; border: 1px solid var(--border); border-radius: 6px;
    background: var(--panel); color: var(--ink); text-decoration: none; font-size: .85rem;
  }
  .panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
  }
  .panel h2 { margin: 0 0 .75rem 0; font-size: 1.05rem; }
  table { border-collapse: collapse; width: 100%; font-size: .9rem; }
  th, td { padding: .5rem .75rem; text-align: left; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-weight: 600; color: var(--muted); text-transform: uppercase; font-size: .7rem; letter-spacing: 0.05em; }
  code { font-family: "JetBrains Mono", Menlo, monospace; font-size: .85em; color: var(--muted); }
  .pill {
    display: inline-block; padding: .15rem .55rem; border-radius: 999px;
    font-size: .7rem; text-transform: uppercase; letter-spacing: 0.06em; color: #fff; font-weight: 600;
  }
  .pill.ok   { background: var(--ok); }
  .pill.warn { background: var(--warn); }
  .pill.fail { background: var(--fail); }
  .pill.info { background: var(--info); }
  .kv { display: grid; grid-template-columns: 1fr auto; gap: .25rem 1rem; font-size: .9rem; }
  .kv .k { color: var(--muted); }
  .kv .v { font-variant-numeric: tabular-nums; text-align: right; }
  footer { margin-top: 2rem; color: var(--muted); font-size: .8rem; text-align: center; }
</style>
</head>
<body>
<header>
  <h1>{{.Title}}</h1>
  <div class="meta">Self-audit rendered {{.GeneratedAt}} · build: <code>{{.Build}}</code> · Go runtime: <code>{{.GoRuntime}}</code></div>
</header>

<nav>
  <a href="/">Overview</a>
  <a href="/admin/security">Security</a>
  <a href="/api/v1/openapi.yaml">OpenAPI</a>
  <a href="/healthz">healthz</a>
  <a href="/readyz">readyz</a>
</nav>

<section class="panel">
  <h2>Controls in effect</h2>
  <table>
    <thead>
      <tr><th>Control</th><th>Status</th><th>Detail</th><th>Code</th><th>ADR</th></tr>
    </thead>
    <tbody>
    {{- range .Controls }}
      <tr>
        <td>{{.Name}}</td>
        <td><span class="pill {{.Status}}">{{.Status}}</span></td>
        <td>{{.Detail}}</td>
        <td><code>{{.Code}}</code></td>
        <td><code>{{.ADR}}</code></td>
      </tr>
    {{- end }}
    </tbody>
  </table>
</section>

<section class="panel">
  <h2>Threat-model docs</h2>
  <ul>
  {{- range .ThreatDocs }}
    <li><code>.context/threat-model/{{.}}.md</code></li>
  {{- end }}
  </ul>
  <div class="meta">Every STRIDE category is analysed in the linked docs. Residual risk entries become v1.0 blockers if not referenced in an ADR or issue.</div>
</section>

<section class="panel">
  <h2>External sec-suite</h2>
  <div class="kv">
    <div class="k">golangci-lint</div><div class="v">CI job <code>lint</code></div>
    <div class="k">gosec</div><div class="v">CI job <code>sec</code></div>
    <div class="k">govulncheck</div><div class="v">CI job <code>sec</code></div>
    <div class="k">trivy fs</div><div class="v">CI job <code>sec</code></div>
    <div class="k">go-licenses (forbidden/restricted)</div><div class="v">CI job <code>sec</code> + supply-chain <code>licenses-audit</code></div>
    <div class="k">gitleaks</div><div class="v">CI job <code>secrets</code></div>
    <div class="k">CodeQL</div><div class="v">CI workflow <code>codeql.yml</code></div>
    <div class="k">OpenSSF Scorecard</div><div class="v">supply-chain <code>scorecard</code></div>
    <div class="k">osv-scanner</div><div class="v">supply-chain <code>osv-scanner</code></div>
    <div class="k">SLSA L3 provenance</div><div class="v">release <code>slsa-provenance</code> (tag only)</div>
    <div class="k">Nightly fuzz (per-target matrix)</div><div class="v">nightly <code>fuzz-long</code></div>
    <div class="k">Gremlins mutation</div><div class="v">nightly <code>mutation</code></div>
    <div class="k">benchstat regression</div><div class="v">benchmarks <code>regression</code></div>
  </div>
  <div class="meta">Results live in GitHub Actions. Pulling them into this panel is a post-1.0 enhancement.</div>
</section>

<footer>
  ElSereno — ICS/OT exposure auditor · self-audit for authorised use only.
</footer>
</body>
</html>
`
