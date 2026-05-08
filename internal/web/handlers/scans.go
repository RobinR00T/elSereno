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
// Five handlers under one prefix:
//
//	POST   /api/v1/scans               submit a new scan job
//	POST   /api/v1/scans/bulk          submit many in one call (v1.69)
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
		mux.HandleFunc("POST /api/v1/scans/bulk", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/scans", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/scans/{id}", serviceUnavailable)
		mux.HandleFunc("POST /api/v1/scans/{id}/cancel", serviceUnavailable)
		return mux
	}
	mux.Handle("POST /api/v1/scans", submitScan(store))
	mux.Handle("POST /api/v1/scans/bulk", bulkSubmitScan(store))
	mux.Handle("GET /api/v1/scans", listScans(store))
	mux.Handle("GET /api/v1/scans/{id}", getScan(store))
	mux.Handle("POST /api/v1/scans/{id}/cancel", cancelScan(store))
	return mux
}

// bulkSubmitRequest is the request body for POST /scans/bulk.
// One Job is submitted per Inputs entry; Plugins + DefaultPort
// are shared across all of them. v1.69+.
type bulkSubmitRequest struct {
	Inputs      []string `json:"inputs"`
	Plugins     []string `json:"plugins,omitempty"`
	DefaultPort int      `json:"default_port,omitempty"`
}

// bulkSubmitResponse is the response body. Submitted carries
// the queued Jobs in the same order as Inputs. Errors carries
// per-input error messages for entries that failed (typically
// empty Inputs strings — Submit's only validation). The
// response always 200s if the request was syntactically valid;
// individual failures don't fail the batch.
type bulkSubmitResponse struct {
	Submitted []scanorch.Job  `json:"submitted"`
	Errors    []bulkErrorItem `json:"errors,omitempty"`
}

type bulkErrorItem struct {
	Index int    `json:"index"`
	Input string `json:"input"`
	Error string `json:"error"`
}

// bulkLimit caps the number of inputs per call. Operators with
// thousands of /24s should batch in pages of 200 — protects the
// dashboard from a single-request DoS that holds the goroutine
// pool.
const bulkLimit = 200

// bulkSubmitScan returns the POST /api/v1/scans/bulk handler.
// Per-input errors are non-fatal: the response always carries
// whatever Submitted; the Errors array reports per-input
// failures with their index in the original Inputs array so
// the client can correlate.
func bulkSubmitScan(store scanorch.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req bulkSubmitRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "scans: malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Inputs) == 0 {
			http.Error(w, "scans: inputs array is required and non-empty", http.StatusBadRequest)
			return
		}
		if len(req.Inputs) > bulkLimit {
			http.Error(w, "scans: bulk submit accepts at most 200 inputs per call", http.StatusBadRequest)
			return
		}
		operator := operatorFromRequest(r)
		resp := bulkSubmitResponse{
			Submitted: make([]scanorch.Job, 0, len(req.Inputs)),
		}
		for i, input := range req.Inputs {
			single := scanorch.SubmitRequest{
				Input:       input,
				Plugins:     req.Plugins,
				DefaultPort: req.DefaultPort,
			}
			job, err := store.Submit(r.Context(), single, operator)
			if err != nil {
				resp.Errors = append(resp.Errors, bulkErrorItem{
					Index: i, Input: input, Error: err.Error(),
				})
				continue
			}
			resp.Submitted = append(resp.Submitted, job)
		}
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, scanResponse{Schema: "api:v1", Data: resp})
	})
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
