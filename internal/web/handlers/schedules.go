package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
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
//	GET    /api/v1/schedules/{id}/audit       audit log (v1.84+)
//	GET    /api/v1/schedules/{id}/runs        run history (v1.92+)
//	DELETE /api/v1/schedules/audit?before=…   prune retention (v1.86+)
//
// A nil store yields 503 — same degraded-deps pattern as the
// other scan-orch endpoints.
//
// v1.84+: the audit store is optional. When non-nil, force-
// overwrite PUTs (carrying `X-Schedule-Force-Overwrite: true`)
// persist a before/after snapshot. nil audit → header is
// honored as "skip If-Match" but no audit row is written.
// /{id}/audit returns 503 in that case.
//
// v1.92+: scanStore is also optional. /{id}/runs returns 503
// when nil; otherwise lists the last N jobs the scheduler
// fired for this schedule (linked via the v1.92
// triggered_by_schedule_id column).
func Schedules(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore, scanStore scanorch.Store) http.Handler {
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
		mux.HandleFunc("GET /api/v1/schedules/{id}/audit", serviceUnavailable)
		mux.HandleFunc("GET /api/v1/schedules/{id}/runs", serviceUnavailable)
		mux.HandleFunc("DELETE /api/v1/schedules/audit", serviceUnavailable)
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
	mux.Handle("PUT /api/v1/schedules/{id}", updateSchedule(store, audit))
	mux.Handle("DELETE /api/v1/schedules/{id}", deleteSchedule(store, audit))
	mux.Handle("POST /api/v1/schedules/{id}/enable", setScheduleEnabled(store, audit, true))
	mux.Handle("POST /api/v1/schedules/{id}/disable", setScheduleEnabled(store, audit, false))
	mux.Handle("GET /api/v1/schedules/{id}/audit", listScheduleAudit(store, audit))
	mux.Handle("GET /api/v1/schedules/{id}/runs", listScheduleRuns(store, scanStore))
	mux.Handle("DELETE /api/v1/schedules/audit", pruneScheduleAudit(audit))
	return mux
}

// listScheduleRuns (v1.92+) handles GET /schedules/{id}/runs.
// Returns the last N jobs (default 50, capped at 1000) the
// scheduler fired for this schedule, sorted newest-first.
//
// The schedule must exist (404 otherwise). 503 when the scan
// store is nil (memory-only deployments that disabled the
// scan store). Empty list is a valid response — a schedule
// that hasn't fired yet returns [].
//
// Optional ?limit= query param: positive int. Default 50.
func listScheduleRuns(store scanorch.ScheduleStore, scanStore scanorch.Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scanStore == nil {
			http.Error(w, "schedules: scan store unavailable", http.StatusServiceUnavailable)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		if _, err := store.Get(r.Context(), id); err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		limit := 50
		if raw := r.URL.Query().Get("limit"); raw != "" {
			n, parseErr := strconv.Atoi(raw)
			if parseErr != nil {
				http.Error(w, "schedules: malformed limit query: "+parseErr.Error(), http.StatusBadRequest)
				return
			}
			if n > 0 {
				limit = n
			}
		}
		jobs, err := scanStore.ListBySchedule(r.Context(), id, limit)
		if err != nil {
			http.Error(w, "schedules: list runs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: jobs})
	})
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
	case errors.Is(err, scanorch.ErrScheduleInvalidAuditRetentionDays):
		http.Error(w, "schedules: audit_retention_days must be >= 0", http.StatusBadRequest)
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
//
// v1.78+: an `If-Match` header (RFC3339 timestamp) enforces
// optimistic locking. The dashboard reads schedule.UpdatedAt
// on Get and sends it back on PUT; if the stored UpdatedAt
// has changed (concurrent edit), the response is 412
// Precondition Failed and the schedule is unchanged.
// Missing/empty header → no precondition check (back-compat
// for v1.74-v1.77 callers + for operator-driven curl scripts
// that don't care about racy edits).
//
// v1.84+: when the request carries
// `X-Schedule-Force-Overwrite: true` AND the audit store is
// non-nil, the handler fetches the pre-update snapshot,
// applies the update, and writes a force_overwrite audit
// event with before/after JSON snapshots. Lets a downstream
// operator audit who overrode whom. The header is honored
// regardless of audit-store presence — the only difference
// is whether the event gets persisted.
func updateSchedule(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore) http.Handler {
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
		if ok := parseIfMatchInto(w, r, &req); !ok {
			return
		}
		// v1.84: optional force-overwrite audit. We snapshot
		// the pre-update state before calling Update so the
		// audit row can record before+after JSON.
		forceOverwrite := r.Header.Get("X-Schedule-Force-Overwrite") == "true"
		var before scanorch.ScanSchedule
		if forceOverwrite && audit != nil {
			b, getErr := store.Get(r.Context(), id)
			if getErr != nil {
				if errors.Is(getErr, scanorch.ErrScheduleNotFound) {
					http.Error(w, "schedules: not found", http.StatusNotFound)
					return
				}
				http.Error(w, "schedules: "+getErr.Error(), http.StatusInternalServerError)
				return
			}
			before = b
		}
		sched, err := store.Update(r.Context(), id, req)
		if err != nil {
			writeUpdateScheduleError(w, err)
			return
		}
		if forceOverwrite && audit != nil {
			recordForceOverwriteAudit(r.Context(), audit, id, operatorFromRequest(r), before, sched, w)
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFire(sched, time.Now().UTC())})
	})
}

// parseIfMatchInto reads the v1.78 If-Match header into
// req.IfMatch. Returns false (after writing 400) on a
// malformed value; true on success or absence.
func parseIfMatchInto(w http.ResponseWriter, r *http.Request, req *scanorch.UpdateScheduleRequest) bool {
	hdr := r.Header.Get("If-Match")
	if hdr == "" {
		return true
	}
	t, parseErr := time.Parse(time.RFC3339Nano, hdr)
	if parseErr != nil {
		t, parseErr = time.Parse(time.RFC3339, hdr)
	}
	if parseErr != nil {
		http.Error(w, "schedules: malformed If-Match header: "+parseErr.Error(), http.StatusBadRequest)
		return false
	}
	req.IfMatch = &t
	return true
}

// writeUpdateScheduleError maps the Update-specific error
// branches (not-found / precondition-failed) on top of the
// shared validation errors.
func writeUpdateScheduleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, scanorch.ErrScheduleNotFound):
		http.Error(w, "schedules: not found", http.StatusNotFound)
	case errors.Is(err, scanorch.ErrSchedulePreconditionFailed):
		http.Error(w, "schedules: precondition failed (schedule was modified — refresh and retry)", http.StatusPreconditionFailed)
	default:
		writeScheduleValidationError(w, err)
	}
}

// recordForceOverwriteAudit is best-effort: a failure to
// persist does NOT reverse the update; we surface a warning
// header so dashboard ops can investigate.
func recordForceOverwriteAudit(ctx context.Context, audit scanorch.ScheduleAuditStore, id, operator string, before, after scanorch.ScanSchedule, w http.ResponseWriter) {
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	if _, err := audit.Append(ctx, scanorch.ScheduleAuditEvent{
		ScheduleID:    id,
		EventType:     scanorch.ScheduleAuditEventForceOverwrite,
		Operator:      operator,
		PayloadBefore: beforeJSON,
		PayloadAfter:  afterJSON,
	}); err != nil {
		w.Header().Set("X-Schedule-Audit-Warning", err.Error())
	}
}

// pruneScheduleAudit (v1.86+) handles DELETE
// /api/v1/schedules/audit?before=<rfc3339>. Removes audit
// events older than the cutoff. Returns the deleted-row
// count.
//
// ?before=… is required (no implicit default — operators
// must opt into a cutoff explicitly). RFC3339 with
// optional fractional seconds.
//
// 503 when the audit store is nil. 400 on missing /
// malformed cutoff.
//
// The endpoint is intentionally NOT scoped per schedule:
// retention policy is global. Per-schedule pruning would
// require additional CHECK CASCADE semantics and is
// deferred.
func pruneScheduleAudit(audit scanorch.ScheduleAuditStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if audit == nil {
			http.Error(w, "schedules: audit log unavailable", http.StatusServiceUnavailable)
			return
		}
		raw := r.URL.Query().Get("before")
		if raw == "" {
			http.Error(w, "schedules: ?before=<rfc3339> is required", http.StatusBadRequest)
			return
		}
		cutoff, parseErr := time.Parse(time.RFC3339Nano, raw)
		if parseErr != nil {
			cutoff, parseErr = time.Parse(time.RFC3339, raw)
		}
		if parseErr != nil {
			http.Error(w, "schedules: malformed ?before= timestamp: "+parseErr.Error(), http.StatusBadRequest)
			return
		}
		count, err := audit.PruneOlderThan(r.Context(), cutoff)
		if err != nil {
			http.Error(w, "schedules: prune audit: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: map[string]any{
			"deleted_count": count,
			"cutoff":        cutoff.UTC(),
		}})
	})
}

// listScheduleAudit (v1.84+) handles GET
// /schedules/{id}/audit. Returns events newest-first. The
// schedule must exist (404 otherwise); a 503 surfaces when
// the audit store is nil (memory deployments or operator
// chose to skip the persistence path).
func listScheduleAudit(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if audit == nil {
			http.Error(w, "schedules: audit log unavailable", http.StatusServiceUnavailable)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		// Verify the schedule exists so callers get a clean
		// 404 instead of an empty-list-for-bad-id ambiguity.
		if _, err := store.Get(r.Context(), id); err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		events, err := audit.ListBySchedule(r.Context(), id)
		if err != nil {
			http.Error(w, "schedules: audit list: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: events})
	})
}

// deleteSchedule (v1.70+) handles DELETE
// /api/v1/schedules/{id}.
//
// v1.88+: when the audit store is non-nil, the handler
// fetches a pre-delete snapshot, performs the DELETE, and
// writes a "delete" audit event with payload_before = full
// schedule + payload_after = JSON null. Migration 00012
// changed the FK to ON DELETE SET NULL so the audit row
// persists with schedule_id NULL'd by the cascade.
//
// Failure to persist the audit row is best-effort (surfaces
// as X-Schedule-Audit-Warning), matching the v1.84
// force-overwrite pattern.
func deleteSchedule(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		var before scanorch.ScanSchedule
		if audit != nil {
			b, getErr := store.Get(r.Context(), id)
			if getErr != nil {
				if errors.Is(getErr, scanorch.ErrScheduleNotFound) {
					http.Error(w, "schedules: not found", http.StatusNotFound)
					return
				}
				http.Error(w, "schedules: "+getErr.Error(), http.StatusInternalServerError)
				return
			}
			before = b
		}
		if err := store.Delete(r.Context(), id); err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if audit != nil {
			beforeJSON, _ := json.Marshal(before)
			if _, auditErr := audit.Append(r.Context(), scanorch.ScheduleAuditEvent{
				ScheduleID:    id,
				EventType:     scanorch.ScheduleAuditEventDelete,
				Operator:      operatorFromRequest(r),
				PayloadBefore: beforeJSON,
				PayloadAfter:  json.RawMessage("null"),
			}); auditErr != nil {
				w.Header().Set("X-Schedule-Audit-Warning", auditErr.Error())
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// setScheduleEnabled (v1.70+) handles
// POST /api/v1/schedules/{id}/enable|disable.
//
// v1.88+: when the audit store is non-nil, the handler
// writes a set_enabled_true / set_enabled_false event with
// payload_before = pre-toggle snapshot + payload_after =
// post-toggle snapshot. Same best-effort failure semantics
// as the v1.84 force-overwrite path.
func setScheduleEnabled(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore, enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		var before scanorch.ScanSchedule
		if audit != nil {
			b, getErr := store.Get(r.Context(), id)
			if getErr != nil {
				if errors.Is(getErr, scanorch.ErrScheduleNotFound) {
					http.Error(w, "schedules: not found", http.StatusNotFound)
					return
				}
				http.Error(w, "schedules: "+getErr.Error(), http.StatusInternalServerError)
				return
			}
			before = b
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
		if audit != nil {
			eventType := scanorch.ScheduleAuditEventSetEnabledFalse
			if enabled {
				eventType = scanorch.ScheduleAuditEventSetEnabledTrue
			}
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(sched)
			if _, auditErr := audit.Append(r.Context(), scanorch.ScheduleAuditEvent{
				ScheduleID:    id,
				EventType:     eventType,
				Operator:      operatorFromRequest(r),
				PayloadBefore: beforeJSON,
				PayloadAfter:  afterJSON,
			}); auditErr != nil {
				w.Header().Set("X-Schedule-Audit-Warning", auditErr.Error())
			}
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
//
// v1.79+: optional `count` query param (default 1, capped at
// scanorch.PreviewNextFiresMaxCount = 10) returns the next N
// firings as `next_fires`. `next_fire_at` is preserved as
// the first element of `next_fires` for back-compat with v1.77/
// v1.78 dashboards. Malformed count → 400.
func previewSchedule() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req scanorch.CreateScheduleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "schedules: malformed JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		count := 1
		if raw := r.URL.Query().Get("count"); raw != "" {
			n, parseErr := strconv.Atoi(raw)
			if parseErr != nil {
				http.Error(w, "schedules: malformed count query: "+parseErr.Error(), http.StatusBadRequest)
				return
			}
			count = n
		}
		fires, err := scanorch.PreviewNextFires(req, time.Now().UTC(), count)
		if err != nil {
			writeScheduleValidationError(w, err)
			return
		}
		// next_fire_at is the first element (back-compat with
		// v1.77/v1.78 single-fire callers). next_fires is the
		// full list — empty when the schedule won't fire.
		var nextFireAt time.Time
		if len(fires) > 0 {
			nextFireAt = fires[0]
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: map[string]any{
			"next_fire_at": nextFireAt,
			"next_fires":   fires,
			"timezone":     req.Timezone,
		}})
	})
}
