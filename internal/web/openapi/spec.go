// Package openapi declares the ElSereno HTTP API contract as Go
// maps so the single source of truth lives alongside the handlers.
// Spec() returns an ordered structure; Marshal renders it to
// deterministic YAML (sorted under stable keys) for the on-disk
// docs/openapi.yaml + the live /api/v1/openapi.yaml endpoint.
package openapi

import (
	"bytes"
	"fmt"

	yaml "go.yaml.in/yaml/v3"
)

// Info holds the envelope metadata.
type Info struct {
	Title       string
	Version     string
	Description string
}

// Operation describes one HTTP verb on a path.
type Operation struct {
	Summary     string
	Description string
	Tags        []string
	// RequestBody (v1.98+) is the optional typed body schema for
	// the operation. Ref is the component name (e.g.
	// "CreateScheduleRequest"); Required marks the body as
	// required. Omit both for GET/DELETE operations that don't
	// take a body.
	RequestBody *RequestBody
	Responses   map[string]Response
}

// RequestBody describes the JSON body shape for an operation.
type RequestBody struct {
	Description string
	Required    bool
	Ref         string
}

// Response is one HTTP response.
type Response struct {
	Description string
	// Ref is an optional "$ref" to a schema under components/schemas.
	Ref string
}

// Path groups the operations on one URL.
type Path struct {
	URL        string
	Operations map[string]Operation // "get" | "post" | …
}

// Schema is a JSON Schema / OpenAPI 3.1 component entry. Expressed
// as raw map so we don't need a full OpenAPI 3.1 AST.
type Schema = map[string]any

// Document is the top-level spec. Build is filled by main() via
// -ldflags to stamp the binary release version into the YAML.
type Document struct {
	Info       Info
	Servers    []string
	Paths      []Path
	Components map[string]Schema
}

// Spec returns the current ElSereno HTTP API spec. Every change to
// internal/web/handlers/api.go must be mirrored here OR a
// TestSpecContract test will flag the drift.
func Spec(buildVersion string) Document {
	if buildVersion == "" {
		buildVersion = "0.1.0-dev"
	}
	return Document{
		Info:       specInfo(buildVersion),
		Servers:    []string{"http://127.0.0.1:8787"},
		Paths:      specPaths(),
		Components: specComponents(),
	}
}

func specInfo(v string) Info {
	return Info{
		Title:   "ElSereno HTTP API",
		Version: v,
		Description: "Read-only HTTP API for ElSereno's dashboard. " +
			"All endpoints return JSON with a `schema` discriminator so " +
			"downstream tools can version against a concrete contract. " +
			"Bearer token auth (ADR-014) gates /api/v1/* when the " +
			"dashboard's auth mode is enabled.",
	}
}

// inputPreviewSpecPaths returns the v1.36+ /api/v1/inputs/preview
// path. Operators wanting to verify an input file from inside
// the dashboard before triggering a (CLI) scan against it.
func inputPreviewSpecPaths() []Path {
	return []Path{
		{URL: "/api/v1/inputs/preview", Operations: map[string]Operation{"get": {
			Summary: "Preview targets parsed from an input source (no scan).",
			Description: "Query params: kind=list:<path>|nmap:<path>|stdin (required), " +
				"default_port=<int> (optional, host-only entries fall back here). " +
				"Returns {count, targets[], truncated}; sample is capped at 200 entries. " +
				"Provider kinds (shodan/censys/fofa/zoomeye/onyphe/internetdb) are NOT " +
				"in scope here — they need credentials + rate-limit tuning that the " +
				"dashboard process intentionally doesn't carry; use the CLI scan verb " +
				"for those. v1.36+.",
			Tags: []string{"inputs"},
			Responses: map[string]Response{
				"200": {Description: "Envelope payload.", Ref: "Envelope"},
				"400": {Description: "Missing kind, unsupported kind (provider kinds are rejected), or bad default_port."},
				"404": {Description: "list:/nmap: path doesn't exist."},
				"500": {Description: "Parse failure inside the underlying parser."},
			},
		}}},
	}
}

// specPaths concatenates the per-group path builders. Splitting
// by "meta" (probes + scoring + plugins + openapi), "stream", and
// "v1.2 DB" keeps each helper under the funlen threshold AND
// gives a grep-friendly anchor for the v1.2 additions.
func specPaths() []Path {
	paths := metaSpecPaths()
	paths = append(paths, streamSpecPath())
	paths = append(paths, dbSpecPaths()...)
	paths = append(paths, inputPreviewSpecPaths()...)
	paths = append(paths, schedulesSpecPaths()...)
	paths = append(paths, schedulesBulkSpecPaths()...)
	return paths
}

// schedulesSpecPaths (v1.96+) returns the /api/v1/schedules/*
// endpoints introduced across v1.70 (CRUD), v1.77 (preview),
// v1.84/v1.86 (audit), v1.92 (runs), v1.93 (clone). Operators
// using the SDK-gen path against /api/v1/openapi.yaml now see
// the full schedule surface. Split into per-aspect helpers to
// keep each function under the funlen cap.
func schedulesSpecPaths() []Path {
	paths := schedulesCRUDPaths()
	paths = append(paths, schedulesToggleAndClonePaths()...)
	paths = append(paths, schedulesObservabilityPaths()...)
	return paths
}

func schedulesCRUDPaths() []Path {
	return []Path{
		schedulesCollectionPath(),
		schedulesItemPath(),
		schedulesPreviewPath(),
	}
}

func schedulesCollectionPath() Path {
	tag := []string{"schedules"}
	return Path{URL: "/api/v1/schedules", Operations: map[string]Operation{
		"get": {
			Summary:     "List scan schedules (v1.70+).",
			Description: "Returns every schedule sorted by name. `next_fire_at` is computed per response (v1.77+).",
			Tags:        tag,
			Responses:   envelopeResponses(),
		},
		"post": {
			Summary: "Create a scan schedule.",
			Description: "Cadence is mutually-exclusive interval_seconds OR cron_expr " +
				"(v1.73+). Optional timezone (IANA, v1.75+). Optional " +
				"audit_retention_days (v1.89+) per-schedule retention override " +
				"(0=inherit global).",
			Tags:        tag,
			RequestBody: &RequestBody{Ref: "CreateScheduleRequest", Required: true},
			Responses: map[string]Response{
				"201": {Description: "Schedule created.", Ref: "ScanSchedule"},
				"400": {Description: "Validation error (name/template/cadence/cron/tz/retention)."},
				"503": {Description: "Schedule store unavailable."},
			},
		},
	}}
}

func schedulesItemPath() Path {
	tag := []string{"schedules"}
	envelopeOr404503 := map[string]Response{
		"200": {Description: "Schedule.", Ref: "ScanSchedule"},
		"404": {Description: "Schedule not found."},
		"503": {Description: "Schedule store unavailable."},
	}
	return Path{URL: "/api/v1/schedules/{id}", Operations: map[string]Operation{
		"get": {Summary: "Get one schedule.", Tags: tag, Responses: envelopeOr404503},
		"put": {
			Summary: "Update a schedule (v1.74+).",
			Description: "Optional If-Match header (RFC3339 of stored updated_at; v1.78+) → " +
				"412 on mismatch. Optional X-Schedule-Force-Overwrite: true → audit " +
				"force-overwrite event (v1.84+).",
			Tags:        tag,
			RequestBody: &RequestBody{Ref: "UpdateScheduleRequest", Required: true},
			Responses: map[string]Response{
				"200": {Description: "Updated schedule.", Ref: "ScanSchedule"},
				"400": {Description: "Validation error."},
				"404": {Description: "Schedule not found."},
				"412": {Description: "Optimistic-locking precondition failed (If-Match mismatch)."},
				"503": {Description: "Schedule store unavailable."},
			},
		},
		"delete": {
			Summary: "Delete a schedule. Audit row persists with schedule_id NULL (v1.88+).",
			Tags:    tag,
			Responses: map[string]Response{
				"204": {Description: "Deleted."},
				"404": {Description: "Schedule not found."},
				"503": {Description: "Schedule store unavailable."},
			},
		},
	}}
}

func schedulesPreviewPath() Path {
	tag := []string{"schedules"}
	return Path{URL: "/api/v1/schedules/preview", Operations: map[string]Operation{
		"post": {
			Summary:     "Preview next fire(s) for a schedule (v1.77+).",
			Description: "Query param: count (1..10, default 1; v1.79+). Returns next_fire_at + next_fires[] + timezone. Validation mirrors POST /schedules.",
			Tags:        tag,
			RequestBody: &RequestBody{Ref: "CreateScheduleRequest", Required: true},
			Responses: map[string]Response{
				"200": {Description: "Preview payload.", Ref: "Envelope"},
				"400": {Description: "Validation error."},
				"503": {Description: "Schedule store unavailable."},
			},
		},
	}}
}

func schedulesToggleAndClonePaths() []Path {
	tag := []string{"schedules"}
	envelopeOr404503 := map[string]Response{
		"200": {Description: "Envelope payload.", Ref: "Envelope"},
		"404": {Description: "Schedule not found."},
		"503": {Description: "Schedule store unavailable."},
	}
	return []Path{
		{URL: "/api/v1/schedules/{id}/enable", Operations: map[string]Operation{
			"post": {Summary: "Enable a schedule. Writes audit (v1.88+).", Tags: tag, Responses: envelopeOr404503},
		}},
		{URL: "/api/v1/schedules/{id}/disable", Operations: map[string]Operation{
			"post": {Summary: "Disable a schedule. Writes audit (v1.88+).", Tags: tag, Responses: envelopeOr404503},
		}},
		{URL: "/api/v1/schedules/{id}/clone", Operations: map[string]Operation{
			"post": {
				Summary: "Duplicate a schedule (v1.93+).",
				Description: "Body fields override the source. Default name is " +
					"`<source.name> (copy)`. Clone always starts Enabled=true; " +
					"LastFiredAt reset; operator = the cloner.",
				Tags:        tag,
				RequestBody: &RequestBody{Ref: "CloneScheduleRequest", Required: false, Description: "Optional override fields; empty body = full copy."},
				Responses: map[string]Response{
					"201": {Description: "Clone created.", Ref: "ScanSchedule"},
					"400": {Description: "Validation error."},
					"404": {Description: "Source schedule not found."},
					"503": {Description: "Schedule store unavailable."},
				},
			},
		}},
	}
}

func schedulesObservabilityPaths() []Path {
	tag := []string{"schedules"}
	return []Path{
		{URL: "/api/v1/schedules/{id}/audit", Operations: map[string]Operation{
			"get": {
				Summary:     "List audit events for a schedule (v1.84+).",
				Description: "Returns events newest-first. event_types: force_overwrite, delete, set_enabled_true, set_enabled_false. data is an array of ScheduleAuditEvent.",
				Tags:        tag,
				Responses: map[string]Response{
					"200": {Description: "Envelope with data: ScheduleAuditEvent[].", Ref: "Envelope"},
					"404": {Description: "Schedule not found."},
					"503": {Description: "Audit store unavailable."},
				},
			},
		}},
		{URL: "/api/v1/schedules/{id}/runs", Operations: map[string]Operation{
			"get": {
				Summary:     "List scheduler-fired jobs for a schedule (v1.92+).",
				Description: "Query param: limit (1..1000, default 50). Returns []Job sorted newest-first via the triggered_by_schedule_id linkage (migration 00014).",
				Tags:        tag,
				Responses: map[string]Response{
					"200": {Description: "Envelope with data: Job[].", Ref: "Envelope"},
					"404": {Description: "Schedule not found."},
					"503": {Description: "Scan store unavailable."},
				},
			},
		}},
		{URL: "/api/v1/schedules/audit", Operations: map[string]Operation{
			"delete": {
				Summary:     "Prune audit events older than ?before=<rfc3339> (v1.86+).",
				Description: "Operator must opt into a cutoff explicitly. Returns {deleted_count, cutoff}.",
				Tags:        tag,
				Responses: map[string]Response{
					"200": {Description: "Prune result.", Ref: "Envelope"},
					"400": {Description: "Missing or malformed ?before."},
					"503": {Description: "Audit store unavailable."},
				},
			},
		}},
	}
}

// schedulesBulkSpecPaths (v1.96+) returns the v1.95 bulk
// pause/resume endpoints. Split from schedulesSpecPaths to
// keep each function under the funlen cap.
func schedulesBulkSpecPaths() []Path {
	tag := []string{"schedules"}
	resp := map[string]Response{
		"200": {Description: "{affected, failed_audits, target_state}.", Ref: "Envelope"},
		"503": {Description: "Schedule store unavailable."},
	}
	return []Path{
		{URL: "/api/v1/schedules/bulk/enable", Operations: map[string]Operation{
			"post": {
				Summary:     "Bulk-enable every schedule (v1.95+).",
				Description: "No body. Returns count of state transitions (already-enabled schedules are no-ops).",
				Tags:        tag,
				Responses:   resp,
			},
		}},
		{URL: "/api/v1/schedules/bulk/disable", Operations: map[string]Operation{
			"post": {
				Summary:     "Bulk-disable every schedule (v1.95+).",
				Description: "No body. Returns count of state transitions (already-disabled schedules are no-ops). Used for planned-maintenance windows.",
				Tags:        tag,
				Responses:   resp,
			},
		}},
		{URL: "/api/v1/schedules/export", Operations: map[string]Operation{
			"get": {
				Summary: "Export schedules for backup (v1.97+).",
				Description: "Query param: format=csv|ndjson|json (default json). " +
					"CSV is 10-column flat (id, name, cadence, enabled, operator, " +
					"created_at, last_fired_at, audit_retention_days, input, plugins). " +
					"NDJSON is round-trippable via per-line POST. " +
					"Content-Disposition: attachment with sensible filenames.",
				Tags: tag,
				Responses: map[string]Response{
					"200": {Description: "Body in the requested format."},
					"400": {Description: "Unsupported format."},
					"503": {Description: "Schedule store unavailable."},
				},
			},
		}},
	}
}

// envelopeResponses is the shared 200 response map for endpoints
// that return the `schema+data` envelope from handlers/api.go.
func envelopeResponses() map[string]Response {
	return map[string]Response{"200": {Description: "Envelope payload.", Ref: "Envelope"}}
}

func metaSpecPaths() []Path {
	return []Path{
		{URL: "/healthz", Operations: map[string]Operation{"get": {
			Summary:   "Liveness probe.",
			Responses: map[string]Response{"200": {Description: "Process is up."}},
		}}},
		{URL: "/readyz", Operations: map[string]Operation{"get": {
			Summary:   "Readiness probe.",
			Responses: map[string]Response{"200": {Description: "Ready to serve traffic (degraded without DB)."}},
		}}},
		{URL: "/api/v1/plugins", Operations: map[string]Operation{"get": {
			Summary:   "List plugins registered in this build.",
			Tags:      []string{"plugins"},
			Responses: envelopeResponses(),
		}}},
		{URL: "/api/v1/scoring", Operations: map[string]Operation{"get": {
			Summary:   "Default scoring weights + severity thresholds.",
			Tags:      []string{"scoring"},
			Responses: envelopeResponses(),
		}}},
		{URL: "/api/v1/health", Operations: map[string]Operation{"get": {
			Summary:   "API-level health with server timestamp.",
			Tags:      []string{"health"},
			Responses: envelopeResponses(),
		}}},
		{URL: "/api/v1/openapi.yaml", Operations: map[string]Operation{"get": {
			Summary:   "Return this OpenAPI 3.1 spec.",
			Tags:      []string{"meta"},
			Responses: map[string]Response{"200": {Description: "OpenAPI 3.1 YAML document."}},
		}}},
	}
}

func streamSpecPath() Path {
	return Path{URL: "/api/v1/stream", Operations: map[string]Operation{"get": {
		Summary: "Server-Sent Events feed (findings / runs / audit).",
		Description: "text/event-stream with `event:`, `id:`, `data:` lines. " +
			"Event kinds: `finding`, `run_start`, `run_end`, `audit`. " +
			"Payloads are JSON objects; schema per-kind is documented " +
			"in internal/web/stream/findings_bridge.go.",
		Tags: []string{"stream"},
		Responses: map[string]Response{
			"200": {Description: "SSE-framed event stream."},
			"503": {Description: "Live feed unavailable (broadcaster not wired)."},
		},
	}}}
}

func dbSpecPaths() []Path {
	dbUnavail := map[string]Response{
		"200": {Description: "Envelope payload.", Ref: "Envelope"},
		"503": {Description: "DB backend unavailable."},
	}
	return []Path{
		{URL: "/api/v1/findings", Operations: map[string]Operation{"get": {
			Summary: "List findings (DB-backed, cursor-paginated).",
			Description: "Query params: severity, protocol, min_score, " +
				"created_after (RFC3339), limit (clamped 1..500, default 50). " +
				"Returned order is created_at DESC; paginate by passing the " +
				"oldest returned row's created_at back as created_after.",
			Tags:      []string{"findings"},
			Responses: dbUnavail,
		}}},
		{URL: "/api/v1/runs", Operations: map[string]Operation{"get": {
			Summary:     "List recent scan runs with per-run finding counts.",
			Description: "Query params: status, started_after (RFC3339), limit (1..100, default 20).",
			Tags:        []string{"runs"},
			Responses:   dbUnavail,
		}}},
		{URL: "/api/v1/triage", Operations: map[string]Operation{"get": {
			Summary:     "Per-severity finding counts for the triage panel.",
			Description: "Returns an array of {severity, count} objects, ordered critical → info. Empty severities are omitted.",
			Tags:        []string{"triage"},
			Responses:   dbUnavail,
		}}},
	}
}

func specComponents() map[string]Schema {
	out := map[string]Schema{
		"Envelope": {
			"type":     "object",
			"required": []string{"schema", "data"},
			"properties": map[string]any{
				"schema": map[string]any{"type": "string", "example": "api:v1"},
				"data":   map[string]any{},
			},
		},
		"Plugin": {
			"type":     "object",
			"required": []string{"name", "build", "default_port", "version"},
			"properties": map[string]any{
				"name":         map[string]any{"type": "string"},
				"description":  map[string]any{"type": "string"},
				"build":        map[string]any{"type": "string", "enum": []string{"default", "offensive"}},
				"default_port": map[string]any{"type": "integer"},
				"version":      map[string]any{"type": "string"},
			},
		},
	}
	// v1.98+: schedule-domain strict schemas.
	for k, v := range scheduleSchemas() {
		out[k] = v
	}
	return out
}

// scheduleSchemas (v1.98+) declares JSON Schema components for
// the scanorch.ScanSchedule + request bodies + supporting types.
// Split into per-group helpers to satisfy funlen.
func scheduleSchemas() map[string]Schema {
	out := map[string]Schema{}
	for k, v := range scheduleRequestSchemas() {
		out[k] = v
	}
	for k, v := range scheduleResponseSchemas() {
		out[k] = v
	}
	return out
}

func scheduleRequestSchemas() map[string]Schema {
	return map[string]Schema{
		"SubmitRequest": {
			"type":     "object",
			"required": []string{"input"},
			"properties": map[string]any{
				"input":        map[string]any{"type": "string", "example": "list:fleet.txt"},
				"plugins":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"default_port": map[string]any{"type": "integer"},
			},
		},
		"CreateScheduleRequest": {
			"type":     "object",
			"required": []string{"name", "template"},
			"properties": map[string]any{
				"name":                 map[string]any{"type": "string", "example": "nightly-fleet"},
				"template":             map[string]any{"$ref": "#/components/schemas/SubmitRequest"},
				"interval_seconds":     map[string]any{"type": "integer", "minimum": 60, "maximum": 604800, "description": "Cadence: interval-based. Mutually exclusive with cron_expr."},
				"cron_expr":            map[string]any{"type": "string", "example": "0 2 * * *", "description": "Cadence: cron-based (5-field). Mutually exclusive with interval_seconds."},
				"timezone":             map[string]any{"type": "string", "example": "Europe/Madrid", "description": "IANA zone for cron evaluation. Ignored for interval schedules."},
				"audit_retention_days": map[string]any{"type": "integer", "minimum": 0, "maximum": 3650, "description": "v1.89+ per-schedule retention override. 0=inherit global, >0=keep N days."},
			},
		},
		"UpdateScheduleRequest": {
			"type":     "object",
			"required": []string{"name", "template"},
			"properties": map[string]any{
				"name":                 map[string]any{"type": "string"},
				"template":             map[string]any{"$ref": "#/components/schemas/SubmitRequest"},
				"interval_seconds":     map[string]any{"type": "integer", "minimum": 60, "maximum": 604800},
				"cron_expr":            map[string]any{"type": "string"},
				"timezone":             map[string]any{"type": "string"},
				"audit_retention_days": map[string]any{"type": "integer", "minimum": 0, "maximum": 3650},
			},
		},
		"CloneScheduleRequest": {
			"type":        "object",
			"description": "Optional body for /schedules/{id}/clone. All fields are overrides; missing fields inherit the source.",
			"properties": map[string]any{
				"name":                 map[string]any{"type": "string", "description": "Empty → '<source.name> (copy)'."},
				"interval_seconds":     map[string]any{"type": "integer", "minimum": 60, "maximum": 604800},
				"cron_expr":            map[string]any{"type": "string"},
				"timezone":             map[string]any{"type": "string"},
				"audit_retention_days": map[string]any{"type": "integer", "minimum": 0, "maximum": 3650},
			},
		},
	}
}

func scheduleResponseSchemas() map[string]Schema {
	out := map[string]Schema{
		"ScanSchedule": scanScheduleSchema(),
		"Stats":        statsSchema(),
		"Job":          jobSchema(),
	}
	for k, v := range scheduleAuditEventSchema() {
		out[k] = v
	}
	return out
}

func scanScheduleSchema() Schema {
	return Schema{
		"type":     "object",
		"required": []string{"id", "name", "template", "enabled", "created_at", "updated_at"},
		"properties": map[string]any{
			"id":                   map[string]any{"type": "string", "example": "abc123def4567890"},
			"name":                 map[string]any{"type": "string"},
			"template":             map[string]any{"$ref": "#/components/schemas/SubmitRequest"},
			"interval_seconds":     map[string]any{"type": "integer"},
			"cron_expr":            map[string]any{"type": "string"},
			"timezone":             map[string]any{"type": "string"},
			"enabled":              map[string]any{"type": "boolean"},
			"operator":             map[string]any{"type": "string"},
			"created_at":           map[string]any{"type": "string", "format": "date-time"},
			"updated_at":           map[string]any{"type": "string", "format": "date-time"},
			"last_fired_at":        map[string]any{"type": "string", "format": "date-time"},
			"next_fire_at":         map[string]any{"type": "string", "format": "date-time", "description": "v1.77+ computed; not persisted."},
			"audit_retention_days": map[string]any{"type": "integer", "description": "v1.89+ per-schedule retention override; 0 = inherit global."},
		},
	}
}

func statsSchema() Schema {
	return Schema{
		"type": "object",
		"properties": map[string]any{
			"targets_seen":    map[string]any{"type": "integer"},
			"targets_scanned": map[string]any{"type": "integer"},
			"findings_count":  map[string]any{"type": "integer"},
		},
	}
}

func jobSchema() Schema {
	return Schema{
		"type":     "object",
		"required": []string{"id", "state", "created_at", "input"},
		"properties": map[string]any{
			"id":                       map[string]any{"type": "string"},
			"state":                    map[string]any{"type": "string", "enum": []string{"queued", "running", "completed", "failed", "cancelled"}},
			"created_at":               map[string]any{"type": "string", "format": "date-time"},
			"started_at":               map[string]any{"type": "string", "format": "date-time"},
			"finished_at":              map[string]any{"type": "string", "format": "date-time"},
			"input":                    map[string]any{"type": "string"},
			"plugins":                  map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"default_port":             map[string]any{"type": "integer"},
			"stats":                    map[string]any{"$ref": "#/components/schemas/Stats"},
			"findings_by_plugin":       map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer"}},
			"error":                    map[string]any{"type": "string"},
			"operator":                 map[string]any{"type": "string"},
			"triggered_by_schedule_id": map[string]any{"type": "string", "description": "v1.92+ FK to schedules.id when scheduler-fired."},
		},
	}
}

func scheduleAuditEventSchema() map[string]Schema {
	return map[string]Schema{
		"ScheduleAuditEvent": {
			"type":     "object",
			"required": []string{"id", "event_type", "operator", "occurred_at", "payload_before", "payload_after"},
			"properties": map[string]any{
				"id":             map[string]any{"type": "string"},
				"schedule_id":    map[string]any{"type": "string", "description": "NULL after v1.88 schedule delete (FK ON DELETE SET NULL)."},
				"event_type":     map[string]any{"type": "string", "enum": []string{"force_overwrite", "delete", "set_enabled_true", "set_enabled_false"}},
				"operator":       map[string]any{"type": "string"},
				"occurred_at":    map[string]any{"type": "string", "format": "date-time"},
				"payload_before": map[string]any{"description": "Full ScanSchedule snapshot pre-event."},
				"payload_after":  map[string]any{"description": "Post-event snapshot; null for delete events."},
			},
		},
	}
}

// Marshal renders d as deterministic OpenAPI 3.1 YAML. The output
// order matches a hand-written spec so diffs are readable.
func Marshal(d Document) ([]byte, error) {
	root := map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":       d.Info.Title,
			"version":     d.Info.Version,
			"description": d.Info.Description,
		},
	}
	if len(d.Servers) > 0 {
		servers := make([]map[string]string, 0, len(d.Servers))
		for _, s := range d.Servers {
			servers = append(servers, map[string]string{"url": s})
		}
		root["servers"] = servers
	}
	if len(d.Paths) > 0 {
		paths := make(map[string]any, len(d.Paths))
		for _, p := range d.Paths {
			ops := map[string]any{}
			for verb, op := range p.Operations {
				ops[verb] = renderOperation(op)
			}
			paths[p.URL] = ops
		}
		root["paths"] = paths
	}
	if len(d.Components) > 0 {
		root["components"] = map[string]any{"schemas": d.Components}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("openapi: encode: %w", err)
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

func renderOperation(op Operation) map[string]any {
	out := map[string]any{}
	if op.Summary != "" {
		out["summary"] = op.Summary
	}
	if op.Description != "" {
		out["description"] = op.Description
	}
	if len(op.Tags) > 0 {
		out["tags"] = op.Tags
	}
	if op.RequestBody != nil && op.RequestBody.Ref != "" {
		rb := map[string]any{
			"content": map[string]any{
				"application/json": map[string]any{
					"schema": map[string]any{"$ref": "#/components/schemas/" + op.RequestBody.Ref},
				},
			},
		}
		if op.RequestBody.Description != "" {
			rb["description"] = op.RequestBody.Description
		}
		if op.RequestBody.Required {
			rb["required"] = true
		}
		out["requestBody"] = rb
	}
	if len(op.Responses) > 0 {
		resps := map[string]any{}
		for code, r := range op.Responses {
			entry := map[string]any{"description": r.Description}
			if r.Ref != "" {
				entry["content"] = map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{"$ref": "#/components/schemas/" + r.Ref},
					},
				}
			}
			resps[code] = entry
		}
		out["responses"] = resps
	}
	return out
}
