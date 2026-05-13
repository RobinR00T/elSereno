package handlers

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
//	POST   /api/v1/schedules/{id}/clone       duplicate (v1.93+)
//	POST   /api/v1/schedules/bulk/enable      bulk-enable every schedule (v1.95+)
//	POST   /api/v1/schedules/bulk/disable     bulk-disable every schedule (v1.95+)
//	GET    /api/v1/schedules/export           CSV/NDJSON backup (v1.97+)
//	POST   /api/v1/schedules/import           NDJSON/JSON restore (v1.99+)
//	GET    /api/v1/schedules/tags             tag-cloud aggregate (v2.5+)
//	POST   /api/v1/schedules/preview          next-fire preview (v1.77+)
//	GET    /api/v1/schedules/{id}/audit       audit log (v1.84+)
//	GET    /api/v1/schedules/{id}/runs        run history (v1.92+)
//	GET    /api/v1/schedules/{id}/stats       aggregate stats (v2.2+)
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
	if store == nil {
		return schedulesUnavailableMux()
	}
	return schedulesActiveMux(store, audit, scanStore)
}

// schedulesUnavailableMux returns the 503-on-everything mux
// used when the operator deployed without a schedule store.
func schedulesUnavailableMux() http.Handler {
	mux := http.NewServeMux()
	serviceUnavailable := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "scan schedules unavailable", http.StatusServiceUnavailable)
	}
	paths := []string{
		"POST /api/v1/schedules",
		"GET /api/v1/schedules",
		"GET /api/v1/schedules/{id}",
		"PUT /api/v1/schedules/{id}",
		"DELETE /api/v1/schedules/{id}",
		"POST /api/v1/schedules/{id}/enable",
		"POST /api/v1/schedules/{id}/disable",
		"POST /api/v1/schedules/preview",
		"GET /api/v1/schedules/{id}/audit",
		"GET /api/v1/schedules/{id}/runs",
		"GET /api/v1/schedules/{id}/stats",
		"POST /api/v1/schedules/{id}/clone",
		"POST /api/v1/schedules/bulk/enable",
		"POST /api/v1/schedules/bulk/disable",
		"GET /api/v1/schedules/export",
		"POST /api/v1/schedules/import",
		"GET /api/v1/schedules/tags",
		"DELETE /api/v1/schedules/audit",
	}
	for _, p := range paths {
		mux.HandleFunc(p, serviceUnavailable)
	}
	return mux
}

// schedulesActiveMux wires the real per-endpoint handlers.
// Split from Schedules() so the funlen rule stays satisfied
// as the endpoint set grows (currently 18 routes; expect
// more in future cycles).
//
// v1.77: /preview is registered BEFORE /{id} so the path
// matcher routes `/preview` to the preview handler instead
// of treating it as an id. Go's net/http mux gives literal
// segments priority over wildcards but we keep the
// declaration order obvious.
func schedulesActiveMux(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore, scanStore scanorch.Store) http.Handler {
	mux := http.NewServeMux()
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
	mux.Handle("GET /api/v1/schedules/{id}/stats", scheduleStats(store, scanStore))
	mux.Handle("POST /api/v1/schedules/{id}/clone", cloneSchedule(store, audit))
	mux.Handle("POST /api/v1/schedules/bulk/enable", bulkSetEnabled(store, audit, true))
	mux.Handle("POST /api/v1/schedules/bulk/disable", bulkSetEnabled(store, audit, false))
	mux.Handle("GET /api/v1/schedules/export", exportSchedules(store))
	mux.Handle("POST /api/v1/schedules/import", importSchedules(store))
	mux.Handle("GET /api/v1/schedules/tags", listScheduleTags(store))
	mux.Handle("DELETE /api/v1/schedules/audit", pruneScheduleAudit(audit))
	return mux
}

// exportSchedules (v1.97+) handles GET /schedules/export. Returns
// every schedule in one of two formats for DR backup or audit
// review:
//
//	?format=csv    → text/csv with a header row.
//	?format=ndjson → application/x-ndjson, one schedule per line.
//	?format=json   → application/json (default; matches /schedules).
//
// CSV is intentionally lossy — only top-level fields. NDJSON is
// the canonical round-trip format: pipe through
// `cat | jq -s '.' | curl -XPOST ... /schedules` is the
// restore recipe (one POST per line; out of scope for this
// endpoint to do server-side).
//
// Content-Disposition is set to `attachment; filename=...`
// so `curl -O` saves a sensible default name.
func exportSchedules(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		schedules, err := store.List(r.Context())
		if err != nil {
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "json"
		}
		switch format {
		case "csv":
			writeSchedulesCSV(w, schedules)
		case "ndjson":
			writeSchedulesNDJSON(w, schedules)
		case "json":
			writeJSON(w, scanResponse{Schema: "api:v1", Data: schedules})
		default:
			http.Error(w, "schedules: unsupported format (csv|ndjson|json)", http.StatusBadRequest)
		}
	})
}

// writeSchedulesCSV emits a 10-column CSV: id, name, cadence
// (compact "interval=Ns" or "cron=expr (tz)"), enabled,
// operator, created_at, last_fired_at, audit_retention_days,
// input, plugins. The dashboard form's editable fields are
// covered + the read-only metadata an admin would want for an
// audit review.
func writeSchedulesCSV(w http.ResponseWriter, schedules []scanorch.ScanSchedule) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="elsereno-schedules.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{
		"id", "name", "cadence", "enabled", "operator",
		"created_at", "last_fired_at", "audit_retention_days",
		"input", "plugins",
	})
	for _, s := range schedules {
		var cadence string
		if s.CronExpr != "" {
			cadence = "cron=" + s.CronExpr
			if s.Timezone != "" {
				cadence += " (" + s.Timezone + ")"
			}
		} else {
			cadence = "interval=" + strconv.Itoa(s.IntervalSeconds) + "s"
		}
		lastFired := ""
		if !s.LastFiredAt.IsZero() {
			lastFired = s.LastFiredAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			s.ID, s.Name, cadence,
			strconv.FormatBool(s.Enabled), s.Operator,
			s.CreatedAt.UTC().Format(time.RFC3339), lastFired,
			strconv.Itoa(s.AuditRetentionDays),
			s.Template.Input,
			strings.Join(s.Template.Plugins, "|"),
		})
	}
}

// writeSchedulesNDJSON emits one canonical JSON object per
// line. Round-trippable through Create — the operator pipe
// `... | jq -c '.' | xargs -I {} curl -XPOST -d '{}' /schedules`
// is the restore recipe. Includes the same fields the API
// returns on GET /schedules (with sensitive fields not stripped
// because the operator already has access to read them).
func writeSchedulesNDJSON(w http.ResponseWriter, schedules []scanorch.ScanSchedule) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition",
		`attachment; filename="elsereno-schedules.ndjson"`)
	enc := json.NewEncoder(w)
	for _, s := range schedules {
		_ = enc.Encode(s) // newline-terminated by Encoder.
	}
}

// bulkSetEnabled (v1.95+) handles
// POST /api/v1/schedules/bulk/{enable|disable}. Toggles every
// schedule's Enabled state to the target value + writes one
// audit event per affected schedule (best-effort, v1.84
// pattern). Returns the count of schedules affected (NOT
// total — only those whose state actually changed).
//
// Designed for planned-maintenance workflows: operator does
// "bulk/disable" before a DB migration, runs the migration,
// then "bulk/enable" to resume. Audit log records who did
// the pause/resume + when, so a compliance review can trace
// the maintenance window.
//
// Pause-then-pause is a no-op for already-disabled schedules
// (no audit row written); same for enable-then-enable. This
// keeps the audit log meaningful — only state transitions
// show up.
func bulkSetEnabled(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore, enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		schedules, err := store.List(r.Context())
		if err != nil {
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		operator := operatorFromRequest(r)
		var affected int
		var failedAudits int
		for _, s := range schedules {
			if s.Enabled == enabled {
				continue // no-op transition; skip audit too
			}
			before := s
			if err := store.SetEnabled(r.Context(), s.ID, enabled); err != nil {
				// Keep going — bulk op is best-effort. Operator
				// can read the response count + diff against
				// List to see which schedules didn't flip.
				continue
			}
			affected++
			if audit == nil {
				continue
			}
			after := before
			after.Enabled = enabled
			eventType := scanorch.ScheduleAuditEventSetEnabledFalse
			if enabled {
				eventType = scanorch.ScheduleAuditEventSetEnabledTrue
			}
			beforeJSON, _ := json.Marshal(before)
			afterJSON, _ := json.Marshal(after)
			if _, auditErr := audit.Append(r.Context(), scanorch.ScheduleAuditEvent{
				ScheduleID:    s.ID,
				EventType:     eventType,
				Operator:      operator,
				PayloadBefore: beforeJSON,
				PayloadAfter:  afterJSON,
			}); auditErr != nil {
				failedAudits++
			}
		}
		if failedAudits > 0 {
			w.Header().Set("X-Schedule-Audit-Warning",
				"some bulk-op audit rows failed to persist")
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: map[string]any{
			"affected":      affected,
			"failed_audits": failedAudits,
			"target_state":  enabled,
		}})
	})
}

// CloneScheduleRequest (v1.93+) is the optional override body
// for POST /schedules/{id}/clone. Any non-zero field replaces
// the corresponding value from the source schedule. Empty body
// = full copy with name defaulting to "<source.name> (copy)".
type CloneScheduleRequest struct {
	// Name overrides the cloned schedule's name. Empty →
	// "<source.name> (copy)". Operators cloning iteratively
	// would otherwise hit name collisions if they typo-skip
	// this field.
	Name string `json:"name,omitempty"`
	// IntervalSeconds + CronExpr + Timezone override cadence.
	// Same XOR rules as Create. Zero values fall back to the
	// source schedule's cadence.
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
	CronExpr        string `json:"cron_expr,omitempty"`
	Timezone        string `json:"timezone,omitempty"`
	// AuditRetentionDays override (v1.89+). Zero → inherit the
	// source's value (which may itself be inherit-global).
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`
}

// cloneSchedule (v1.93+) handles POST /schedules/{id}/clone.
// Creates a new schedule by copying the source + applying any
// overrides from the body. Default name is "<source> (copy)"
// to avoid silent collisions (Names are non-unique but the
// dashboard sorts by name so collision-prone clones make ops
// life worse).
//
// Returns 201 + the new schedule. 404 if source unknown.
// 400 on a body that parses but fails validation (the
// validation is identical to Create's).
//
// Notable copy semantics:
//   - Enabled = true on the clone, regardless of source.
//     Operators cloning a disabled schedule almost always
//     want to test the clone, not preserve the disabled
//     state.
//   - LastFiredAt does NOT carry over (clone starts
//     "never-fired"; new ID = new cadence anchor).
//   - Operator on the clone = the cloner (X-Operator
//     header), NOT the original schedule's operator.
//     Preserves provenance per-creation; original schedule
//     unaffected.
func cloneSchedule(store scanorch.ScheduleStore, audit scanorch.ScheduleAuditStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "schedules: id is required", http.StatusBadRequest)
			return
		}
		// Body is optional; an empty body decodes cleanly to
		// the zero-value struct. EOF on Decode also fine —
		// just means "no body".
		var override CloneScheduleRequest
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&override); err != nil {
				http.Error(w, "schedules: malformed JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		source, err := store.Get(r.Context(), id)
		if err != nil {
			if errors.Is(err, scanorch.ErrScheduleNotFound) {
				http.Error(w, "schedules: not found", http.StatusNotFound)
				return
			}
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		req := buildCloneRequest(source, override)
		operator := operatorFromRequest(r)
		clone, err := store.Create(r.Context(), req, operator)
		if err != nil {
			writeScheduleValidationError(w, err)
			return
		}
		// v2.1: best-effort cloned_from audit row keyed on
		// clone.ID. payload_before = source snapshot, after =
		// clone snapshot. Failure surfaces as
		// X-Schedule-Audit-Warning per v1.84 pattern.
		if audit != nil {
			recordClonedFromAudit(r.Context(), audit, clone.ID, operator, source, clone, w)
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, scanResponse{Schema: "api:v1", Data: withNextFire(clone, time.Now().UTC())})
	})
}

// recordClonedFromAudit is best-effort: a failure to persist
// does NOT undo the clone; we surface a warning header so
// dashboard ops can investigate (mirrors v1.84 force-overwrite
// + v1.88 delete patterns).
func recordClonedFromAudit(ctx context.Context, audit scanorch.ScheduleAuditStore, cloneID, operator string, source, clone scanorch.ScanSchedule, w http.ResponseWriter) {
	beforeJSON, _ := json.Marshal(source)
	afterJSON, _ := json.Marshal(clone)
	if _, err := audit.Append(ctx, scanorch.ScheduleAuditEvent{
		ScheduleID:    cloneID,
		EventType:     scanorch.ScheduleAuditEventClonedFrom,
		Operator:      operator,
		PayloadBefore: beforeJSON,
		PayloadAfter:  afterJSON,
	}); err != nil {
		w.Header().Set("X-Schedule-Audit-Warning", err.Error())
	}
}

// buildCloneRequest copies the source schedule + applies
// overrides. Default name is "<source.name> (copy)" to keep
// collisions visible without forcing operators to type a
// fresh name on every clone.
func buildCloneRequest(source scanorch.ScanSchedule, override CloneScheduleRequest) scanorch.CreateScheduleRequest {
	name := override.Name
	if name == "" {
		name = source.Name + " (copy)"
	}
	req := scanorch.CreateScheduleRequest{
		Name:               name,
		Template:           source.Template,
		IntervalSeconds:    source.IntervalSeconds,
		CronExpr:           source.CronExpr,
		Timezone:           source.Timezone,
		AuditRetentionDays: source.AuditRetentionDays,
	}
	// Cadence override: when the operator specifies a cadence
	// in the body, that wins. The cadence-XOR rule applies —
	// they must specify exactly one of interval/cron if
	// overriding either. Empty body fields = use source's
	// cadence as-is.
	if override.IntervalSeconds > 0 || override.CronExpr != "" {
		req.IntervalSeconds = override.IntervalSeconds
		req.CronExpr = override.CronExpr
		req.Timezone = override.Timezone
	}
	if override.AuditRetentionDays > 0 {
		req.AuditRetentionDays = override.AuditRetentionDays
	}
	return req
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
// v2.0+: optional ?before=<rfc3339> cursor for keyset
// pagination. Operators paginate by reading the response's
// `next_before` value (the oldest returned row's created_at)
// and passing it back on the next call. `next_before` is
// omitted when no more rows exist.
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
		limit, lerr := parseRunsLimit(r)
		if lerr != nil {
			http.Error(w, "schedules: "+lerr.Error(), http.StatusBadRequest)
			return
		}
		before, berr := parseRunsBefore(r)
		if berr != nil {
			http.Error(w, "schedules: "+berr.Error(), http.StatusBadRequest)
			return
		}
		jobs, err := scanStore.ListByScheduleBefore(r.Context(), id, before, limit)
		if err != nil {
			http.Error(w, "schedules: list runs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		payload := buildRunsResponse(jobs, limit)
		// v2.7: ETag — runs are append-only at the head of
		// the list; old pages are stable.
		writeJSONWithETag(w, r, scanResponse{Schema: "api:v1", Data: payload})
	})
}

// scheduleStats (v2.2+) handles GET /schedules/{id}/stats.
// Query param `?days=N` (1..365, default 7) sets the window.
// Returns aggregate run stats over the window.
//
// 404 unknown schedule. 503 nil scan store. 400 on bad days
// param.
func scheduleStats(store scanorch.ScheduleStore, scanStore scanorch.Store) http.Handler {
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
		days, derr := parseStatsDays(r)
		if derr != nil {
			http.Error(w, "schedules: "+derr.Error(), http.StatusBadRequest)
			return
		}
		since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
		stats, err := scanStore.StatsBySchedule(r.Context(), id, since)
		if err != nil {
			http.Error(w, "schedules: stats: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: map[string]any{
			"schedule_id":          stats.ScheduleID,
			"window_days":          days,
			"since":                stats.Since.Format(time.RFC3339),
			"now":                  stats.Now.Format(time.RFC3339),
			"total_runs":           stats.TotalRuns,
			"completed":            stats.Completed,
			"failed":               stats.Failed,
			"cancelled":            stats.Cancelled,
			"running":              stats.Running,
			"queued":               stats.Queued,
			"success_rate":         stats.SuccessRate,
			"avg_duration_seconds": stats.AvgDurationSeconds,
			"avg_findings_per_run": stats.AvgFindingsPerRun,
			"total_findings":       stats.TotalFindings,
		}})
	})
}

// parseStatsDays validates ?days=. Empty → default 7. Clamped
// to [1, 365].
func parseStatsDays(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("days")
	if raw == "" {
		return 7, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("malformed days query: %w", err)
	}
	if n < 1 {
		n = 1
	}
	if n > 365 {
		n = 365
	}
	return n, nil
}

// parseRunsLimit validates ?limit=. Empty → default 50.
func parseRunsLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("malformed limit query: %w", err)
	}
	if n <= 0 {
		return 50, nil
	}
	return n, nil
}

// parseRunsBefore validates ?before= (RFC3339). Empty → zero
// time (no cursor).
func parseRunsBefore(r *http.Request) (time.Time, error) {
	raw := r.URL.Query().Get("before")
	if raw == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t, err = time.Parse(time.RFC3339, raw)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("malformed before query (RFC3339): %w", err)
	}
	return t, nil
}

// buildRunsResponse wraps the jobs slice + emits the
// next_before cursor when the page is full (which means more
// older rows likely exist; the operator can paginate). When
// fewer rows than `limit` are returned we know the page is
// the last + omit next_before.
func buildRunsResponse(jobs []scanorch.Job, limit int) map[string]any {
	out := map[string]any{
		"items": jobs,
	}
	if len(jobs) >= limit && limit > 0 {
		// Oldest row in the page = the next cursor anchor.
		oldest := jobs[len(jobs)-1].CreatedAt
		if !oldest.IsZero() {
			out["next_before"] = oldest.UTC().Format(time.RFC3339Nano)
		}
	}
	return out
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
	case errors.Is(err, scanorch.ErrScheduleInvalidTag):
		http.Error(w, "schedules: tag invalid (1..32 chars, [a-z0-9_-] only)", http.StatusBadRequest)
	case errors.Is(err, scanorch.ErrScheduleTooManyTags):
		http.Error(w, "schedules: too many tags (max 10)", http.StatusBadRequest)
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
		// v2.4: optional ?tag= filter via the new ListByTag
		// store method. Empty tag → full list (back-compat).
		// v2.9: multi-tag via repeated ?tag=a&tag=b + ?op=
		// (and|or, default and). Single-tag query stays
		// back-compat.
		tags := r.URL.Query()["tag"]
		op := strings.ToLower(r.URL.Query().Get("op"))
		if op == "" {
			op = scanorch.TagOpAnd
		}
		if op != scanorch.TagOpAnd && op != scanorch.TagOpOr {
			http.Error(w, "schedules: op must be 'and' or 'or'", http.StatusBadRequest)
			return
		}
		var (
			schedules []scanorch.ScanSchedule
			err       error
		)
		switch {
		case len(tags) == 0:
			schedules, err = store.List(r.Context())
		case len(tags) == 1:
			schedules, err = store.ListByTag(r.Context(), tags[0])
		default:
			schedules, err = store.ListByTags(r.Context(), tags, op)
		}
		if err != nil {
			http.Error(w, "schedules: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// v2.7: deliberately NOT using ETag here. NextFireAt
		// is computed at second-resolution `now` → the hash
		// changes on every call regardless of schedule
		// content. ETag is applied to lower-churn endpoints
		// (/tags, /{id}/audit, /{id}/runs, /{id}/stats).
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
		// v2.7: ETag — audit events are immutable past
		// records; new appends invalidate the hash but
		// otherwise polls return 304.
		writeJSONWithETag(w, r, scanResponse{Schema: "api:v1", Data: events})
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

// Conflict-resolution strategies for v1.99 schedule import.
const (
	importConflictSkip      = "skip"
	importConflictOverwrite = "overwrite"
	importConflictRename    = "rename"
)

// Per-row outcomes from v1.99 schedule import.
const (
	importOutcomeCreated     = "created"
	importOutcomeRenamed     = "renamed"
	importOutcomeOverwritten = "overwritten"
	importOutcomeSkipped     = "skipped"
	importOutcomeError       = "error"
)

// listScheduleTags (v2.5+) handles GET /schedules/tags. Returns
// the aggregate (tag → count) across every schedule, sorted by
// count DESC + tag ASC. Used by the dashboard tag-cloud +
// autocomplete; operators graph tag distribution to spot gaps
// ("how many schedules are tagged 'prod'?").
func listScheduleTags(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counts, err := store.TagCounts(r.Context())
		if err != nil {
			http.Error(w, "schedules: tag counts: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Always-non-nil slice so JSON renders `"tags": []`
		// when empty (dashboards don't need null-checks).
		if counts == nil {
			counts = []scanorch.TagCount{}
		}
		// v2.7: ETag — tag-counts is low-churn (tags rarely
		// change), heavy-poll (dashboard widget refreshes
		// every 30s). 304 path saves bandwidth.
		writeJSONWithETag(w, r, scanResponse{Schema: "api:v1", Data: counts})
	})
}

// ScheduleImportResult (v1.99+) is the per-row outcome of
// importSchedules. The aggregate response has a counts struct
// + an items list with one entry per input line.
type ScheduleImportResult struct {
	Index    int    `json:"index"`           // 0-based input row.
	Name     string `json:"name"`            // Imported name (possibly renamed).
	Outcome  string `json:"outcome"`         // created | skipped | overwritten | renamed | error
	ID       string `json:"id,omitempty"`    // ID of the resulting schedule (when not skipped/error).
	ErrorMsg string `json:"error,omitempty"` // Set when outcome == "error".
}

// importSchedules (v1.99+) handles POST /api/v1/schedules/import.
// Body is either NDJSON (one ScanSchedule per line; matches
// the v1.97 export `format=ndjson` output) or a JSON array.
// Disambiguated by Content-Type:
//
//	application/x-ndjson → NDJSON line-delimited.
//	application/json     → JSON array of ScanSchedule.
//	other / missing      → try NDJSON first; fall back to JSON array.
//
// Query param `?on_conflict=skip|overwrite|rename` (default
// `skip`) controls behaviour when a schedule with the same
// name already exists.
//
//	skip       → leave existing alone; outcome="skipped".
//	overwrite  → Update the existing in-place; outcome="overwritten".
//	rename     → append " (imported)" to name; Create; outcome="renamed".
//
// Server generates fresh IDs in every case — operators
// importing from another deployment shouldn't have to coordinate
// IDs. UpdatedAt + CreatedAt are stamped fresh on Create;
// LastFiredAt is dropped (the import isn't a fire).
//
// Returns:
//
//	{
//	  "schema": "api:v1",
//	  "data": {
//	    "imported": <total_created+renamed>,
//	    "skipped":  <count>,
//	    "overwritten": <count>,
//	    "renamed":  <count>,
//	    "errors":   <count>,
//	    "items":    [ScheduleImportResult, ...]
//	  }
//	}
func importSchedules(store scanorch.ScheduleStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strategy := r.URL.Query().Get("on_conflict")
		if strategy == "" {
			strategy = importConflictSkip
		}
		if !isValidConflictStrategy(strategy) {
			http.Error(w, "schedules: on_conflict must be skip|overwrite|rename", http.StatusBadRequest)
			return
		}
		rows, err := decodeImportBody(r)
		if err != nil {
			http.Error(w, "schedules: malformed import body: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Build name → existing map once so per-row conflict
		// lookups are O(1). The List could grow stale during
		// the loop if another writer is mutating concurrently;
		// import is a maintenance operation usually run after
		// bulk/disable (v1.95), so the race is benign.
		existing, err := buildScheduleNameIndex(r.Context(), store)
		if err != nil {
			http.Error(w, "schedules: list for import: "+err.Error(), http.StatusInternalServerError)
			return
		}
		operator := operatorFromRequest(r)
		items := make([]ScheduleImportResult, 0, len(rows))
		var counts importCounts
		for i, row := range rows {
			result := applyImportRow(r.Context(), store, existing, operator, strategy, i, row)
			items = append(items, result)
			counts.bump(result.Outcome)
		}
		writeJSON(w, scanResponse{Schema: "api:v1", Data: map[string]any{
			"imported":    counts.imported,
			"skipped":     counts.skipped,
			"overwritten": counts.overwritten,
			"renamed":     counts.renamed,
			"errors":      counts.errors,
			"items":       items,
		}})
	})
}

type importCounts struct {
	imported, skipped, overwritten, renamed, errors int
}

func (c *importCounts) bump(outcome string) {
	switch outcome {
	case importOutcomeCreated:
		c.imported++
	case importOutcomeRenamed:
		c.imported++
		c.renamed++
	case importOutcomeOverwritten:
		c.overwritten++
	case importOutcomeSkipped:
		c.skipped++
	case importOutcomeError:
		c.errors++
	}
}

// isValidConflictStrategy guards the on_conflict query param.
func isValidConflictStrategy(s string) bool {
	switch s {
	case importConflictSkip, importConflictOverwrite, importConflictRename:
		return true
	}
	return false
}

// decodeImportBody parses the request body as NDJSON (one
// ScanSchedule per line) OR as a single JSON array. The
// Content-Type header is preferred; on unknown/missing types
// we try NDJSON first then fall back to JSON array.
func decodeImportBody(r *http.Request) ([]scanorch.ScanSchedule, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	ct := r.Header.Get("Content-Type")
	switch ct {
	case "application/x-ndjson":
		return decodeNDJSON(body)
	case "application/json":
		return decodeJSONArray(body)
	}
	// Heuristic for missing/unknown CT: a trimmed body that
	// starts with `[` is a JSON array; otherwise NDJSON. Tests
	// + curl users without an explicit -H benefit.
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return decodeJSONArray(body)
	}
	return decodeNDJSON(body)
}

// decodeNDJSON parses one ScanSchedule per non-empty line.
func decodeNDJSON(body []byte) ([]scanorch.ScanSchedule, error) {
	var out []scanorch.ScanSchedule
	dec := json.NewDecoder(bytes.NewReader(body))
	for dec.More() {
		var s scanorch.ScanSchedule
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("ndjson decode: %w", err)
		}
		out = append(out, s)
	}
	return out, nil
}

// decodeJSONArray parses [ScanSchedule, …].
func decodeJSONArray(body []byte) ([]scanorch.ScanSchedule, error) {
	var out []scanorch.ScanSchedule
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("json array decode: %w", err)
	}
	return out, nil
}

// buildScheduleNameIndex builds a name → ScanSchedule map from
// the current Store.List. Used by importSchedules to detect
// conflicts in O(1) per row.
func buildScheduleNameIndex(ctx context.Context, store scanorch.ScheduleStore) (map[string]scanorch.ScanSchedule, error) {
	all, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]scanorch.ScanSchedule, len(all))
	for _, s := range all {
		out[s.Name] = s
	}
	return out, nil
}

// applyImportRow handles one input row per the resolution
// strategy. Updates `existing` so a same-name row appearing
// twice in the input (or renamed) doesn't collide with itself.
func applyImportRow(ctx context.Context, store scanorch.ScheduleStore, existing map[string]scanorch.ScanSchedule, operator, strategy string, index int, row scanorch.ScanSchedule) ScheduleImportResult {
	res := ScheduleImportResult{Index: index, Name: row.Name}
	prior, conflict := existing[row.Name]
	if conflict {
		switch strategy {
		case importConflictSkip:
			res.Outcome = importOutcomeSkipped
			res.ID = prior.ID
			return res
		case importConflictOverwrite:
			return applyImportOverwrite(ctx, store, existing, prior, row, res)
		case importConflictRename:
			row.Name = uniqueRenameFor(row.Name, existing)
			res.Name = row.Name
			res = applyImportCreate(ctx, store, existing, operator, row, res)
			res.Outcome = importOutcomeRenamed
			return res
		}
	}
	return applyImportCreate(ctx, store, existing, operator, row, res)
}

// applyImportCreate calls Create + updates the existing index.
func applyImportCreate(ctx context.Context, store scanorch.ScheduleStore, existing map[string]scanorch.ScanSchedule, operator string, row scanorch.ScanSchedule, base ScheduleImportResult) ScheduleImportResult {
	req := scanorch.CreateScheduleRequest{
		Name:               row.Name,
		Template:           row.Template,
		IntervalSeconds:    row.IntervalSeconds,
		CronExpr:           row.CronExpr,
		Timezone:           row.Timezone,
		AuditRetentionDays: row.AuditRetentionDays,
	}
	created, err := store.Create(ctx, req, operator)
	if err != nil {
		base.Outcome = importOutcomeError
		base.ErrorMsg = err.Error()
		return base
	}
	existing[created.Name] = created
	base.Outcome = importOutcomeCreated
	base.ID = created.ID
	return base
}

// applyImportOverwrite Updates the existing schedule in-place.
// Preserves the existing ID + CreatedAt + LastFiredAt
// (Update's semantics).
func applyImportOverwrite(ctx context.Context, store scanorch.ScheduleStore, existing map[string]scanorch.ScanSchedule, prior, row scanorch.ScanSchedule, base ScheduleImportResult) ScheduleImportResult {
	req := scanorch.UpdateScheduleRequest{
		Name:               row.Name,
		Template:           row.Template,
		IntervalSeconds:    row.IntervalSeconds,
		CronExpr:           row.CronExpr,
		Timezone:           row.Timezone,
		AuditRetentionDays: row.AuditRetentionDays,
		// IfMatch nil → skip optimistic-lock check (operator
		// importing knows they're stomping the row).
	}
	updated, err := store.Update(ctx, prior.ID, req)
	if err != nil {
		base.Outcome = importOutcomeError
		base.ErrorMsg = err.Error()
		return base
	}
	existing[updated.Name] = updated
	base.Outcome = importOutcomeOverwritten
	base.ID = updated.ID
	return base
}

// uniqueRenameFor returns the input name with " (imported)"
// suffixed; if THAT collides too, appends an integer suffix
// until a free name is found. Bounded loop: ~1000 attempts.
func uniqueRenameFor(base string, existing map[string]scanorch.ScanSchedule) string {
	candidate := base + " (imported)"
	if _, conflict := existing[candidate]; !conflict {
		return candidate
	}
	for i := 2; i < 1000; i++ {
		candidate = base + " (imported " + strconv.Itoa(i) + ")"
		if _, conflict := existing[candidate]; !conflict {
			return candidate
		}
	}
	// Bounded fallback: append a timestamp suffix so we don't
	// loop forever even in absurd-input scenarios.
	return base + " (imported " + strconv.FormatInt(time.Now().UnixNano(), 10) + ")"
}
