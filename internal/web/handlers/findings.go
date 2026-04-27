package handlers

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
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
//	format=json|csv     v1.18 chunk 1: csv → text/csv body +
//	                    `Content-Disposition: attachment` so the
//	                    browser downloads `findings-<RFC3339>.csv`.
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
		if strings.EqualFold(r.URL.Query().Get("format"), "csv") {
			writeFindingsCSV(w, rows)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: rows})
	})
}

// writeFindingsCSV emits rows as RFC 4180 CSV with a leading
// header row. Columns: id, run_id, target_id, protocol,
// severity, score, created_at (RFC3339Nano UTC), factors
// (`name=value;...` semicolon-separated, factor names sorted
// alphabetically for stable diffs).
//
// Content-Disposition is set so curl-default-stdout AND browser
// "Save Link As" both produce a sensibly-named file. Filename
// includes the wall-clock UTC for traceability — operators
// often grab multiple snapshots during a single change window.
func writeFindingsCSV(w http.ResponseWriter, rows []repo.Finding) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="findings-%s.csv"`, time.Now().UTC().Format("20060102T150405Z")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "run_id", "target_id", "protocol", "severity", "score", "created_at", "factors"})
	for _, r := range rows {
		_ = cw.Write([]string{
			r.ID,
			r.RunID,
			r.TargetID,
			r.Protocol,
			r.Severity,
			strconv.Itoa(r.Score),
			r.CreatedAt.UTC().Format(time.RFC3339Nano),
			canonFactorsCSVField(r.Factors),
		})
	}
	cw.Flush()
}

// canonFactorsCSVField renders the per-finding factor map as
// `name=value;name=value` with names sorted alphabetically.
// Empty map → empty string. Stable across calls so diffs of
// CSV exports are clean.
func canonFactorsCSVField(factors map[string]int) string {
	if len(factors) == 0 {
		return ""
	}
	keys := make([]string, 0, len(factors))
	for k := range factors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(factors[k]))
	}
	return b.String()
}

// FindingsDiff returns the `GET /api/v1/findings/diff` handler.
// v1.18 chunk 2: operators running weekly scans see what
// changed between two runs without grepping JSON. Required
// query params: `old=<run_id>` + `new=<run_id>`. Match across
// runs is by (target_id, protocol) — the same exposure
// rediscovered on the next scan is "persisting" even though
// its DB row gets a fresh UUID.
//
// Response envelope mirrors the other v1 endpoints:
//
//	{
//	  "schema": "api:v1",
//	  "data":   { "new": [...], "resolved": [...], "persisting": [...] }
//	}
func FindingsDiff(q repo.Querier) http.Handler {
	if q == nil {
		return unavailableHandler("findings_diff backend unavailable")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		oldRun := strings.TrimSpace(v.Get("old"))
		newRun := strings.TrimSpace(v.Get("new"))
		if oldRun == "" || newRun == "" {
			http.Error(w, "findings/diff: required query params: old=<run_id>&new=<run_id>", http.StatusBadRequest)
			return
		}
		if oldRun == newRun {
			http.Error(w, "findings/diff: old and new must be distinct run ids", http.StatusBadRequest)
			return
		}
		diff, err := repo.DiffFindings(r.Context(), q, oldRun, newRun)
		if err != nil {
			http.Error(w, "findings/diff: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, envelope{Schema: "api:" + APIVersion, Data: diff})
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
