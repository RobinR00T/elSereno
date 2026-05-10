package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"local/elsereno/internal/scanorch"
)

// Schedules returns the scan-schedule endpoints (v1.70+).
//
//	POST   /api/v1/schedules                  create a schedule
//	GET    /api/v1/schedules                  list schedules
//	GET    /api/v1/schedules/{id}             one schedule
//	PUT    /api/v1/schedules/{id}             edit (v1.74+)
//	DELETE /api/v1/schedules/{id}             remove
//	POST   /api/v1/schedules/{id}/enable
//	POST   /api/v1/schedules/{id}/disable
//
// A nil store yields 503 — same degraded-deps pattern as the
// other scan-orch endpoints.
func Schedules(store scanorch.ScheduleStore) http.Handler {
	mux := http.NewServeMux()
	if store == nil {
		serviceUnavailable := func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "scan schedules unavailable", http.StatusServiceUnavailable)
		}
		mux.HandleFunc("POST /api/v1/schedules", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/schedules", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/schedules/{id}", serviceUnavailable)
		mux.HandleFunc("PUT /api/v1/schedules/{id}", serviceUnavailable)
		mux.HandleFunc("DELETE /api/v1/schedules/{id}", serviceUnavailable)
		mux.HandleFunc("POST /api/v1/schedules/{id}/enable", serviceUnavailable)
		mux.HandleFunc("POST /api/v1/schedules/{id}/disable", serviceUnavailable)
		return mux
	}
	mux.Handle("POST /api/v1/schedules", createSchedule(store))
	mux.Handle("GET /api/v1/schedules", listSchedules(store))
	mux.Handle("GET /api/v1/schedules/{id}", getSchedule(store))
	mux.Handle("PUT /api/v1/schedules/{id}", updateSchedule(store))
	mux.Handle("DELETE /api/v1/schedules/{id}", deleteSchedule(store))
	mux.Handle("POST /api/v1/schedules/{id}/enable", setScheduleEnabled(store, true))
	mux.Handle("POST /api/v1/schedules/{id}/disable", setScheduleEnabled(store, false))
	return mux
}

func createSchedule(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req scanorch.CreateScheduleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "schedules: malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		operator := operatorFromRequest(r)
		sched, err := store.Create(r.Context(), req, operator)
		if err != nil {
			switch {
			case errors.Is(err, scanorch.ErrScheduleNameRequired):
				http.Error(w, "schedules: name is required", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleTemplateInputRequired):
				http.Error(w, "schedules: template.input is required", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleCadenceRequired):
				http.Error(w, "schedules: cadence is required (interval_seconds or cron_expr)", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleCadenceConflict):
				http.Error(w, "schedules: cannot set both interval_seconds and cron_expr", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrCronInvalidField), errors.Is(err, scanorch.ErrCronWrongFieldCount):
				http.Error(w, "schedules: invalid cron expression: "+err.Error(), http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleInvalidTimezone):
				http.Error(w, "schedules: "+err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, scanResponse{Schema: "api:v1", Data: sched})
	})
}

func listSchedules(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		schedules, err := store.List(r.Context())
		if err != nil {
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: schedules})
	})
}

func getSchedule(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		sched, err := store.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: sched})
	})
}

// updateSchedule (v1.74+) handles PUT /schedules/{id}. Body
// is JSON UpdateScheduleRequest; response is the updated
// schedule. Same validation surface as createSchedule
// (name + template + cadence) — error mapping reuses the
// same sentinels.
func updateSchedule(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		var req scanorch.UpdateScheduleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "schedules: malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		sched, err := store.Update(r.Context(), id, req)
		if err != nil {
			switch {
			case errors.Is(err, scanorch.ErrScheduleNotFound):
				http.Error(w, "schedules: not found", http.StatusNotFound)
			case errors.Is(err, scanorch.ErrScheduleNameRequired):
				http.Error(w, "schedules: name is required", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleTemplateInputRequired):
				http.Error(w, "schedules: template.input is required", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleCadenceRequired):
				http.Error(w, "schedules: cadence is required (interval_seconds or cron_expr)", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleCadenceConflict):
				http.Error(w, "schedules: cannot set both interval_seconds and cron_expr", http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrCronInvalidField), errors.Is(err, scanorch.ErrCronWrongFieldCount):
				http.Error(w, "schedules: invalid cron expression: "+err.Error(), http.StatusBadRequest)
			case errors.Is(err, scanorch.ErrScheduleInvalidTimezone):
				http.Error(w, "schedules: "+err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: sched})
	})
}

func deleteSchedule(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		if err := store.Delete(r.Context(), id); err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func setScheduleEnabled(store scanorch.ScheduleStore, enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		if err := store.SetEnabled(r.Context(), id, enabled); err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Re-fetch + return so the caller has the new state.
		sched, err := store.Get(r.Context(), id)
		if err != nil {
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: sched})
	})
}
