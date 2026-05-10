package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

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
//	POST   /api/v1/schedules/preview          next-fire preview (v1.77+)
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
		mux.HandleFunc("POST /api/v1/schedules/preview", serviceUnavailable)
		return mux
	}
	// v1.77: /preview is registered BEFORE /{id} so the path
	// matcher routes `/preview` to the preview handler instead
	// of treating it as an id. Go's net/http mux gives literal
	// segments priority over wildcards but we keep the
	// declaration order obvious.
	mux.Handle("POST /api/v1/schedules/preview", previewSchedule())
	mux.Handle("POST /api/v1/schedules", createSchedule(store))
	mux.Handle("GET /api/v1/schedules", listSchedules(store))
	mux.Handle("GET /api/v1/schedules/{id}", getSchedule(store))
	mux.Handle("PUT /api/v1/schedules/{id}", updateSchedule(store))
	mux.Handle("DELETE /api/v1/schedules/{id}", deleteSchedule(store))
	mux.Handle("POST /api/v1/schedules/{id}/enable", setScheduleEnabled(store, true))
	mux.Handle("POST /api/v1/schedules/{id}/disable", setScheduleEnabled(store, false))
	return mux
}

// withNextFire (v1.77+) populates s.NextFireAt before
// serializing a single schedule. The store leaves it at zero
// because it's a derived value — the REST layer is the right
// place to compute "next fire" because that's where the
// "now" reference is meaningful.
func withNextFire(s scanorch.ScanSchedule, now time.Time) scanorch.ScanSchedule {
	s.NextFireAt = s.NextFire(now)
	return s
}

// withNextFireSlice maps over a list of schedules.
func withNextFireSlice(s []scanorch.ScanSchedule, now time.Time) []scanorch.ScanSchedule {
	for i := range s {
		s[i] = withNextFire(s[i], now)
	}
	return s
}

// writeScheduleValidationError maps the schedule validation
// sentinels (Create + Update + Preview share these rules) to
// HTTP responses. Caller passes nil err only for the
// not-found case which is handled separately.
//
// v1.77+: extracted from createSchedule + previewSchedule to
// satisfy the dupl linter — the Create/Update/Preview paths
// all map the same set of sentinels to 400.
func writeScheduleValidationError(w http.ResponseWriter, err error) {
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
			writeScheduleValidationError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFire(sched, time.Now().UTC())})
	})
}

func listSchedules(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		schedules, err := store.List(r.Context())
		if err != nil {
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFireSlice(schedules, time.Now().UTC())})
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
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFire(sched, time.Now().UTC())})
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
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			writeScheduleValidationError(w, err)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFire(sched, time.Now().UTC())})
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
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFire(sched, time.Now().UTC())})
	})
}

// previewSchedule (v1.77+) handles POST /schedules/preview.
// Body is a CreateScheduleRequest; response surfaces the
// predicted next fire time so operators can see what their
// cadence will produce before committing the schedule.
//
// The preview is store-independent — it doesn't touch the
// ScheduleStore. Validation surface mirrors createSchedule
// (same sentinels for cadence + cron + timezone errors).
func previewSchedule() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req scanorch.CreateScheduleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "schedules: malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		next, err := scanorch.PreviewNextFire(req, time.Now().UTC())
		if err != nil {
			writeScheduleValidationError(w, err)
			return
		}
		// Surface the timezone alongside next_fire_at so the
		// dashboard can render the local-clock string without
		// re-parsing the request.
		writeJSON(w, scanResponse{Schema: "api:v1", Data: map[string]any{
			"next_fire_at": next,
			"timezone":     req.Timezone,
		}})
	})
}
