package handlers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"local/elsereno/internal/repo"
)

// Audit returns the `GET /api/v1/audit` handler. Backs the
// dashboard's audit-feed panel (v1.19 chunk 1). Requires a
// repo.Querier; returns 503 when nil so the dashboard can
// render a "no DB" placeholder rather than a hard error.
//
// Query params:
//
//	event_type=<canonical_event>   one of audit.EventType values
//	actor=<actor>                  e.g. system / operator / <uuid>
//	occurred_after=<rfc3339>       cursor for older-than pagination
//	limit=<int>                    [1, 500]; default 50
func Audit(q repo.Querier) http.Handler {
	if q == nil {
		return unavailableHandler("audit backend unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aq := parseAuditQuery(r.URL.Query())
		rows, err := repo.ListAuditLog(r.Context(), q, aq)
		if err != nil {
			http.Error(w, "audit: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: rows})
	})
}

// AuditCadence returns the `GET /api/v1/audit/cadence` handler.
// v1.19 chunk 2: backs the reload-cadence panel + any future
// "events over time" charts. Defaults to the last 7 days; the
// `days` query param clamps to [1, 90]. Optional `event_type`
// filter scopes the bucket to one event class (typical use:
// proxy_allowlist_reload).
func AuditCadence(q repo.Querier) http.Handler {
	if q == nil {
		return unavailableHandler("audit_cadence backend unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		eventType := strings.TrimSpace(v.Get("event_type"))
		days := 7
		if s := v.Get("days"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				days = n
			}
		}
		rows, err := repo.ListAuditCadence(r.Context(), q, eventType, days)
		if err != nil {
			http.Error(w, "audit_cadence: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: rows})
	})
}

// parseAuditQuery extracts AuditQuery fields from URL values.
// Invalid ints / timestamps silently default to zero (which
// translates to "no filter") rather than returning 400 — same
// convention as parseFindingsQuery.
func parseAuditQuery(v url.Values) repo.AuditQuery {
	q := repo.AuditQuery{
		EventType: v.Get("event_type"),
		Actor:     v.Get("actor"),
	}
	if s := v.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			q.Limit = n
		}
	}
	if s := v.Get("occurred_after"); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			q.OccurredAfter = t
		}
	}
	return q
}
