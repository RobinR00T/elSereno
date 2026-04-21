package handlers

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"local/elsereno/internal/repo"
)

// Findings returns the `GET /api/v1/findings` handler. Requires
// a repo.Querier (usually a *pgxpool.Pool). Returns 503 when
// querier is nil — the dashboard can still render skeleton
// panels in that case.
//
// Query params:
//
//	severity=critical|high|medium|low|info
//	protocol=<name>
//	min_score=<int>
//	created_after=<rfc3339>
//	limit=<int>
func Findings(q repo.Querier) http.Handler {
	if q == nil {
		return unavailableHandler("findings backend unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fq := parseFindingsQuery(r.URL.Query())
		rows, err := repo.ListFindings(r.Context(), q, fq)
		if err != nil {
			http.Error(w, "findings: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: rows})
	})
}

// Runs returns the `GET /api/v1/runs` handler.
func Runs(q repo.Querier) http.Handler {
	if q == nil {
		return unavailableHandler("runs backend unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rq := parseRunsQuery(r.URL.Query())
		rows, err := repo.ListRuns(r.Context(), q, rq)
		if err != nil {
			http.Error(w, "runs: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: rows})
	})
}

// Triage returns the `GET /api/v1/triage` handler. Emits per-
// severity counts for the dashboard's triage chip row.
func Triage(q repo.Querier) http.Handler {
	if q == nil {
		return unavailableHandler("triage backend unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := repo.Triage(r.Context(), q)
		if err != nil {
			http.Error(w, "triage: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: rows})
	})
}

// parseFindingsQuery extracts FindingsQuery fields from URL
// values. Invalid ints silently default to zero (which
// translates to "no filter") rather than returning 400 — the
// dashboard is the primary consumer and we'd rather render a
// partial page than a red error box.
func parseFindingsQuery(v url.Values) repo.FindingsQuery {
	q := repo.FindingsQuery{
		Severity: v.Get("severity"),
		Protocol: v.Get("protocol"),
	}
	if s := v.Get("min_score"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			q.MinScore = n
		}
	}
	if s := v.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			q.Limit = n
		}
	}
	if s := v.Get("created_after"); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			q.CreatedAfter = t
		}
	}
	return q
}

func parseRunsQuery(v url.Values) repo.RunsQuery {
	q := repo.RunsQuery{
		Status: v.Get("status"),
	}
	if s := v.Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			q.Limit = n
		}
	}
	if s := v.Get("started_after"); s != "" {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			q.StartedAfter = t
		}
	}
	return q
}

// unavailableHandler is the 503 stand-in for endpoints whose
// repo dependency wasn't wired. The dashboard checks the status
// on GET to decide whether to render the skeleton-only panel.
func unavailableHandler(msg string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, msg, http.StatusServiceUnavailable)
	})
}
