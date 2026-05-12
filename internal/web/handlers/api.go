package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/repo"
	"local/elsereno/internal/scanorch"
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
	if deps.Broadcaster != nil {
		mux.Handle("GET /api/v1/stream", Stream(deps.Broadcaster))
	} else {
		mux.HandleFunc("GET /api/v1/stream", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "live feed unavailable", http.StatusServiceUnavailable)
		})
	}
	mux.Handle("GET /api/v1/findings", Findings(deps.Querier))
	mux.Handle("GET /api/v1/findings/diff", FindingsDiff(deps.Querier))
	mux.Handle("GET /api/v1/runs", Runs(deps.Querier))
	mux.Handle("GET /api/v1/triage", Triage(deps.Querier))
	mux.Handle("GET /api/v1/audit", Audit(deps.Querier))
	mux.Handle("GET /api/v1/audit/cadence", AuditCadence(deps.Querier))
	// v1.36+: input-preview parity with the `scan` / `tui`
	// CLI verbs. Read-only — does NOT run a scan; just parses
	// the input file + returns the resolved targets so
	// operators can verify a list:/nmap: file from inside the
	// dashboard before invoking the (CLI) scan against it.
	// Provider kinds (shodan: / etc.) are out of scope here
	// because they need creds + rate-limit tuning that the
	// dashboard process intentionally doesn't carry.
	mux.Handle("GET /api/v1/inputs/preview", PreviewInput())
	// v1.58 chunk 1: scan orchestration endpoints. Three
	// handlers (POST /scans, GET /scans, GET /scans/{id}) are
	// served by the Scans sub-router.
	scansHandler := Scans(deps.ScanStore)
	mux.Handle("POST /api/v1/scans", scansHandler)
	mux.Handle("POST /api/v1/scans/bulk", scansHandler)
	mux.Handle("GET /api/v1/scans", scansHandler)
	mux.Handle("GET /api/v1/scans/{id}", scansHandler)
	mux.Handle("POST /api/v1/scans/{id}/cancel", scansHandler)
	// v1.70: scan-schedules sub-router.
	// v1.92: scanStore is passed in so /{id}/runs can list jobs
	// the scheduler fired for the schedule.
	schedulesHandler := Schedules(deps.ScheduleStore, deps.ScheduleAuditStore, deps.ScanStore)
	mux.Handle("POST /api/v1/schedules", schedulesHandler)
	mux.Handle("GET /api/v1/schedules", schedulesHandler)
	mux.Handle("GET /api/v1/schedules/{id}", schedulesHandler)
	mux.Handle("PUT /api/v1/schedules/{id}", schedulesHandler)
	mux.Handle("DELETE /api/v1/schedules/{id}", schedulesHandler)
	mux.Handle("POST /api/v1/schedules/{id}/enable", schedulesHandler)
	mux.Handle("POST /api/v1/schedules/{id}/disable", schedulesHandler)
	mux.Handle("GET /api/v1/schedules/{id}/audit", schedulesHandler)
	mux.Handle("GET /api/v1/schedules/{id}/runs", schedulesHandler)
	return mux
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
