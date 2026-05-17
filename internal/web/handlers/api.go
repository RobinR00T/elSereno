package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/repo"
	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/auth"
	"local/elsereno/internal/web/openapi"
	"local/elsereno/internal/web/stream"
)

// APIV1Deps bundles the optional dependencies APIV1 needs. Each
// field is optional; missing deps downgrade the corresponding
// endpoint to 503 rather than breaking the whole router. This
// lets `serve` run without a DB pool (e.g. a quick dashboard
// preview) while still exposing health + plugins + scoring +
// OpenAPI.
type APIV1Deps struct {
	// Broadcaster backs GET /api/v1/stream. Nil → 503.
	Broadcaster *stream.Broadcaster
	// Querier backs GET /api/v1/findings, /runs, /triage. Nil → 503.
	Querier repo.Querier
	// ScanStore backs POST/GET /api/v1/scans (v1.58 chunk 1).
	// Nil → 503 (operator running serve without orchestration
	// configured will see "scan orchestration unavailable").
	ScanStore scanorch.Store
	// ScheduleStore (v1.70+) backs /api/v1/schedules. Nil →
	// 503. Schedules fire saved Job templates on a cadence
	// via a Scheduler goroutine in cmd_serve.
	ScheduleStore scanorch.ScheduleStore
	// ScheduleAuditStore (v1.84+) backs the force-overwrite
	// audit path. Nil = audit-disabled — force-overwrite
	// PUTs still succeed but no row is persisted, and
	// GET /api/v1/schedules/{id}/audit returns 503.
	ScheduleAuditStore scanorch.ScheduleAuditStore
	// AuthVerifier (v2.40+) enforces OIDC bearer-token validation
	// + role-based access control on mutating endpoints. Nil OR
	// v.Enabled()==false → back-compat dev mode (every route
	// passes the upstream auth middleware unchanged; X-Operator
	// header carries identity). When enabled, role rules are:
	//   - GET routes: viewer minimum.
	//   - POST/PUT/DELETE on schedules: operator minimum.
	//   - Bulk + import + tag-rename + audit-delete: admin.
	AuthVerifier *auth.Verifier
	// PoolStatter (v2.52+) is the optional pgxpool.Pool that
	// backs GET /api/v1/health/pool. Nil → 503 ("pool not
	// configured"); set to a *pgxpool.Pool in cmd_serve when
	// the DB pool exists. Operators graph TotalConns /
	// IdleConns / AcquireDuration to size their fleet under
	// load.
	PoolStatter PoolStatter
}

// PoolStatter is the minimum surface the pool-health endpoint
// needs. *pgxpool.Pool satisfies it (Stat() *pgxpool.Stat);
// tests use a synthetic stub.
type PoolStatter interface {
	Stat() *PoolStat
}

// PoolStat is the local shape of pgxpool.Stat-relevant fields
// — flattened so the handler doesn't pull pgxpool into its
// import graph. Adapter in cmd_serve converts the real
// pgxpool.Stat into this shape.
type PoolStat struct {
	AcquireCount            int64         `json:"acquire_count"`
	AcquireDuration         time.Duration `json:"acquire_duration_ns"`
	AcquiredConns           int32         `json:"acquired_conns"`
	CanceledAcquireCount    int64         `json:"canceled_acquire_count"`
	ConstructingConns       int32         `json:"constructing_conns"`
	EmptyAcquireCount       int64         `json:"empty_acquire_count"`
	IdleConns               int32         `json:"idle_conns"`
	MaxConns                int32         `json:"max_conns"`
	TotalConns              int32         `json:"total_conns"`
	NewConnsCount           int64         `json:"new_conns_count"`
	MaxLifetimeDestroyCount int64         `json:"max_lifetime_destroy_count"`
	MaxIdleDestroyCount     int64         `json:"max_idle_destroy_count"`
}

// APIV1 returns the /api/v1 sub-router. Endpoints:
//
//	GET /api/v1/plugins       read-only registered-plugin list
//	GET /api/v1/scoring       ADR-006 weights + severity thresholds
//	GET /api/v1/health        API-level health with server timestamp
//	GET /api/v1/openapi.yaml  code-sourced OpenAPI 3.1 spec
//	GET /api/v1/stream        SSE fan-out (findings/runs/audit)
//	GET /api/v1/findings      DB-backed findings list (v1.2)
//	GET /api/v1/runs          DB-backed runs list (v1.2)
//	GET /api/v1/triage        per-severity counts (v1.2)
//
// See APIV1Deps for the optional-dependency model.
func APIV1(deps APIV1Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/plugins", listPlugins)
	mux.HandleFunc("GET /api/v1/scoring", getScoring)
	mux.HandleFunc("GET /api/v1/health", getHealth)
	mux.HandleFunc("GET /api/v1/openapi.yaml", getOpenAPI)
	// v2.52: /health/pool exposes pgxpool runtime stats so
	// operators can graph DB pressure under load. 503 when
	// no Pool is wired (memory-mode deployments).
	mux.Handle("GET /api/v1/health/pool", poolHealth(deps.PoolStatter))
	if deps.Broadcaster != nil {
		mux.Handle("GET /api/v1/stream", Stream(deps.Broadcaster))
	} else {
		mux.HandleFunc("GET /api/v1/stream", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "live feed unavailable", http.StatusServiceUnavailable)
		})
	}
	// v2.48: extend per-route OIDC binding to /findings,
	// /runs, /triage, /audit, /audit/cadence. All read-only
	// → viewer minimum. wrapWithRole no-ops when AuthVerifier
	// is nil/disabled (back-compat preserved).
	v := deps.AuthVerifier
	mux.Handle("GET /api/v1/findings", wrapWithRole(v, auth.RoleViewer, Findings(deps.Querier)))
	mux.Handle("GET /api/v1/findings/diff", wrapWithRole(v, auth.RoleViewer, FindingsDiff(deps.Querier)))
	mux.Handle("GET /api/v1/runs", wrapWithRole(v, auth.RoleViewer, Runs(deps.Querier)))
	mux.Handle("GET /api/v1/triage", wrapWithRole(v, auth.RoleViewer, Triage(deps.Querier)))
	mux.Handle("GET /api/v1/audit", wrapWithRole(v, auth.RoleViewer, Audit(deps.Querier)))
	mux.Handle("GET /api/v1/audit/cadence", wrapWithRole(v, auth.RoleViewer, AuditCadence(deps.Querier)))
	// v1.36+: input-preview parity with the `scan` / `tui`
	// CLI verbs. Read-only — does NOT run a scan; just parses
	// the input file + returns the resolved targets so
	// operators can verify a list:/nmap: file from inside the
	// dashboard before invoking the (CLI) scan against it.
	// Provider kinds (shodan: / etc.) are out of scope here
	// because they need creds + rate-limit tuning that the
	// dashboard process intentionally doesn't carry.
	// v2.48: viewer-level for preview (read-only side-effect-free).
	mux.Handle("GET /api/v1/inputs/preview", wrapWithRole(v, auth.RoleViewer, PreviewInput()))
	// v1.58 chunk 1: scan orchestration endpoints. Three
	// handlers (POST /scans, GET /scans, GET /scans/{id}) are
	// served by the Scans sub-router.
	//
	// v2.48 role split:
	//   GET /scans + GET /scans/{id}                 → viewer
	//   POST /scans + POST /scans/bulk               → operator
	//   POST /scans/{id}/cancel                      → operator
	scansHandler := Scans(deps.ScanStore)
	mux.Handle("POST /api/v1/scans", wrapWithRole(v, auth.RoleOperator, scansHandler))
	mux.Handle("POST /api/v1/scans/bulk", wrapWithRole(v, auth.RoleOperator, scansHandler))
	mux.Handle("GET /api/v1/scans", wrapWithRole(v, auth.RoleViewer, scansHandler))
	mux.Handle("GET /api/v1/scans/{id}", wrapWithRole(v, auth.RoleViewer, scansHandler))
	mux.Handle("POST /api/v1/scans/{id}/cancel", wrapWithRole(v, auth.RoleOperator, scansHandler))
	mountScheduleRoutes(mux, deps)
	return mux
}

// mountScheduleRoutes (v2.16+, v2.40 role-aware) registers
// every /api/v1/schedules/* route on `mux` with per-route OIDC
// role enforcement. Extracted so APIV1 stays under the funlen
// statement cap as the schedule surface grows.
//
// Role rules (when deps.AuthVerifier is enabled):
//   - GET routes  → viewer.
//   - PUT / DELETE / POST on a single schedule → operator.
//   - Bulk endpoints + tag-rename + import → admin.
//
// When AuthVerifier is nil or disabled, every route passes
// through unchanged (preserves the v1.58 X-Operator workflow).
func mountScheduleRoutes(mux *http.ServeMux, deps APIV1Deps) {
	h := Schedules(deps.ScheduleStore, deps.ScheduleAuditStore, deps.ScanStore)
	v := deps.AuthVerifier
	for _, entry := range scheduleRoutes() {
		guarded := wrapWithRole(v, entry.role, h)
		mux.Handle(entry.pattern, guarded)
	}
}

// scheduleRouteEntry is one declarative routing record: HTTP
// method + path + minimum role required.
type scheduleRouteEntry struct {
	pattern string
	role    auth.Role
}

// scheduleRoutes is the canonical (pattern → role) table.
// Single source of truth for both mountScheduleRoutes and the
// future docs/openapi spec annotation cycle.
func scheduleRoutes() []scheduleRouteEntry {
	return []scheduleRouteEntry{
		// Reads — viewer.
		{"GET /api/v1/schedules", auth.RoleViewer},
		{"GET /api/v1/schedules/{id}", auth.RoleViewer},
		{"GET /api/v1/schedules/{id}/audit", auth.RoleViewer},
		{"GET /api/v1/schedules/{id}/runs", auth.RoleViewer},
		{"GET /api/v1/schedules/{id}/stats", auth.RoleViewer},
		{"GET /api/v1/schedules/{id}/clones", auth.RoleViewer},
		{"GET /api/v1/schedules/{id}/stats/timeseries", auth.RoleViewer},
		{"GET /api/v1/schedules/export", auth.RoleViewer},
		{"GET /api/v1/schedules/tags", auth.RoleViewer},
		// Single-schedule mutations — operator.
		{"POST /api/v1/schedules", auth.RoleOperator},
		{"PUT /api/v1/schedules/{id}", auth.RoleOperator},
		{"DELETE /api/v1/schedules/{id}", auth.RoleOperator},
		{"POST /api/v1/schedules/{id}/enable", auth.RoleOperator},
		{"POST /api/v1/schedules/{id}/disable", auth.RoleOperator},
		{"POST /api/v1/schedules/{id}/clone", auth.RoleOperator},
		// Fleet-wide / destructive — admin.
		{"POST /api/v1/schedules/tags/rename", auth.RoleAdmin},
		{"POST /api/v1/schedules/bulk/enable", auth.RoleAdmin},
		{"POST /api/v1/schedules/bulk/disable", auth.RoleAdmin},
		{"POST /api/v1/schedules/import", auth.RoleAdmin},
	}
}

// wrapWithRole composes the role-check middleware around h.
// Nil verifier or disabled verifier → returns h unchanged
// (zero-overhead back-compat).
func wrapWithRole(v *auth.Verifier, required auth.Role, h http.Handler) http.Handler {
	if v == nil || !v.Enabled() {
		return h
	}
	return v.RequireRole(required, h)
}

// getOpenAPI serves the code-sourced OpenAPI 3.1 YAML. The same
// spec is snapshot to docs/openapi.yaml on release.
func getOpenAPI(w http.ResponseWriter, _ *http.Request) {
	body, err := openapi.Marshal(openapi.Spec(""))
	if err != nil {
		http.Error(w, "openapi: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// APIVersion is the contract version surfaced in responses.
const APIVersion = "v1"

type pluginResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Build       string `json:"build"`
	DefaultPort int    `json:"default_port"`
	Version     string `json:"version"`
}

type envelope struct {
	Schema string `json:"schema"`
	Data   any    `json:"data"`
}

func listPlugins(w http.ResponseWriter, _ *http.Request) {
	plugins := core.RegisteredPlugins()
	out := make([]pluginResponse, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, pluginResponse{
			Name:        p.Name,
			Description: p.Description,
			Build:       p.Build,
			DefaultPort: int(p.DefaultPort),
			Version:     p.Version,
		})
	}
	writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: out})
}

type scoringResponse struct {
	Weights    map[string]float64 `json:"weights"`
	Thresholds map[string]int     `json:"severity_thresholds"`
}

func getScoring(w http.ResponseWriter, _ *http.Request) {
	// Static copy of ADR-006 defaults. Live loader bind arrives with
	// the dashboard MVP's scoring panel.
	body := scoringResponse{
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
	writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: body})
}

type healthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

func getHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, envelope{
		Schema: "api:" + APIVersion,
		Data:   healthResponse{Status: "ok", Timestamp: time.Now().UTC()},
	})
}

// poolHealth (v2.52+) returns the pgxpool runtime stats as
// JSON. 503 when no PoolStatter is configured (memory-mode
// or pre-DB-bootstrap deployments).
func poolHealth(ps PoolStatter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if ps == nil {
			http.Error(w, "pool not configured (memory-mode or pre-DB)",
				http.StatusServiceUnavailable)
			return
		}
		s := ps.Stat()
		if s == nil {
			http.Error(w, "pool stat unavailable",
				http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, envelope{
			Schema: "api:" + APIVersion,
			Data: map[string]any{
				"pool":      s,
				"timestamp": time.Now().UTC(),
			},
		})
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeJSONWithETag (v2.7+) is the cache-aware variant of
// writeJSON. Marshals v, computes a SHA-256 ETag over the
// payload, and:
//
//   - If the request's `If-None-Match` matches the computed
//     ETag → respond 304 Not Modified with the ETag header
//     (body omitted).
//   - Otherwise → 200 with ETag header + the body.
//
// Cache-Control is `private, max-age=0, must-revalidate` so
// downstream proxies can cache but the dashboard always
// revalidates. Matches the dashboard's 30s polling pattern
// for read-heavy endpoints (schedules list, tag-counts,
// audit history).
//
// ETag is the first 16 hex chars of SHA-256 (64 bits of
// collision-resistance; sufficient for cache validation +
// keeps the header small).
func writeJSONWithETag(w http.ResponseWriter, r *http.Request, v any) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		http.Error(w, "marshal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"` // 16 hex chars + quotes (RFC 7232).
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=0, must-revalidate")
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
	_, _ = w.Write([]byte("\n"))
}
