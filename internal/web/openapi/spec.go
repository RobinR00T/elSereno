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
	Responses   map[string]Response
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
	return paths
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
	return map[string]Schema{
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
