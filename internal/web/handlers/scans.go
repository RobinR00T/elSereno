package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"local/elsereno/internal/scanorch"
)

// note: writeJSON lives in api.go; this file re-uses it.

// Scans returns the dashboard scan-orchestration endpoints.
// Four handlers under one prefix:
//
//	POST   /api/v1/scans               submit a new scan job
//	GET    /api/v1/scans               list jobs (newest first)
//	GET    /api/v1/scans/{id}          one job by ID
//	POST   /api/v1/scans/{id}/cancel   cancel a queued/running job (v1.59)
//
// A nil Store yields 503 from each endpoint, mirroring the
// degraded-deps pattern used by Findings/Runs/Triage.
func Scans(store scanorch.Store) http.Handler {
	mux := http.NewServeMux()
	if store == nil {
		serviceUnavailable := func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "scan orchestration unavailable", http.StatusServiceUnavailable)
		}
		mux.HandleFunc("POST /api/v1/scans", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/scans", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/scans/{id}", serviceUnavailable)
		mux.HandleFunc("POST /api/v1/scans/{id}/cancel", serviceUnavailable)
		return mux
	}
	mux.Handle("POST /api/v1/scans", submitScan(store))
	mux.Handle("GET /api/v1/scans", listScans(store))
	mux.Handle("GET /api/v1/scans/{id}", getScan(store))
	mux.Handle("POST /api/v1/scans/{id}/cancel", cancelScan(store))
	return mux
}

// scanResponse is the wrapper envelope around scan-related
// payloads. Mirrors the api:v1 envelope used by other endpoints.
type scanResponse struct {
	Schema string      `json:"schema"`
	Data   interface{} `json:"data"`
}

// submitScan returns the POST handler. Body is JSON
// SubmitRequest; response is the freshly-queued Job.
func submitScan(store scanorch.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req scanorch.SubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "scans: malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		operator := operatorFromRequest(r)
		job, err := store.Submit(r.Context(), req, operator)
		if err != nil {
			if errors.Is(err, scanorch.ErrInputRequired) {
				http.Error(w, "scans: input is required", http.StatusBadRequest)
				return
			}
			http.Error(w, "scans: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, scanResponse{Schema: "api:v1", Data: job})
	})
}

// listScans returns the GET-list handler. Optional `limit` query
// param clamped to [1, 100], default 20.
func listScans(store scanorch.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r.URL.Query().Get("limit"))
		jobs, err := store.List(r.Context(), limit)
		if err != nil {
			http.Error(w, "scans: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: jobs})
	})
}

// cancelScan returns the POST cancel handler. Allowed for
// queued + running jobs; refuses with 409 if already terminal.
func cancelScan(store scanorch.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "scans: id is required", http.StatusBadRequest)
			return
		}
		job, err := store.Transition(r.Context(), id, scanorch.StateCancelled, scanorch.TransitionFields{})
		if err != nil {
			switch {
			case errors.Is(err, scanorch.ErrJobNotFound):
				http.Error(w, "scans: job not found", http.StatusNotFound)
			case errors.Is(err, scanorch.ErrInvalidTransition):
				http.Error(w, "scans: job is already in a terminal state", http.StatusConflict)
			default:
				http.Error(w, "scans: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: job})
	})
}

// getScan returns the GET-one handler.
func getScan(store scanorch.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "scans: id is required", http.StatusBadRequest)
			return
		}
		job, err := store.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, scanorch.ErrJobNotFound) {
				http.Error(w, "scans: job not found", http.StatusNotFound)
				return
			}
			http.Error(w, "scans: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: job})
	})
}

// parseLimit clamps the limit query param to [1, 100], default 20.
func parseLimit(raw string) int {
	if raw == "" {
		return 20
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 20
	}
	if n > 100 {
		return 100
	}
	return n
}

// operatorFromRequest extracts the operator identity from the
// request. v1.58 chunk 1 reads the X-Operator header set by the
// upstream auth middleware (or empty for unauthenticated dev
// runs); a future chunk wires this through the shared session
// context that the audit + findings endpoints already use.
func operatorFromRequest(r *http.Request) string {
	if v := r.Header.Get("X-Operator"); v != "" {
		return v
	}
	return ""
}

// writeJSON is shared with api.go (defined there). Re-using the
// existing helper to keep response shapes consistent.
