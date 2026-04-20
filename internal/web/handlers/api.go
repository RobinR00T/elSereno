package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/web/openapi"
)

// APIV1 returns the /api/v1 sub-router. The endpoints surface
// read-only data: plugins, scoring weights, health. Data-returning
// endpoints (findings, runs, targets) fill in once DB-backed writes
// land alongside the F4 proxy framework.
func APIV1() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/plugins", listPlugins)
	mux.HandleFunc("GET /api/v1/scoring", getScoring)
	mux.HandleFunc("GET /api/v1/health", getHealth)
	mux.HandleFunc("GET /api/v1/openapi.yaml", getOpenAPI)
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
