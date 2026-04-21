package openapi_test

import (
	"strings"
	"testing"

	"local/elsereno/internal/web/openapi"
)

func TestSpec_IncludesAllKnownPaths(t *testing.T) {
	doc := openapi.Spec("1.0.0")
	b, err := openapi.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	// Must render a valid OpenAPI 3.1 envelope.
	if !strings.Contains(body, "openapi: 3.1.0") {
		t.Fatalf("openapi version missing:\n%s", body)
	}
	// Every path handled by internal/web/handlers/api.go MUST appear.
	for _, p := range []string{
		"/healthz",
		"/readyz",
		"/api/v1/plugins",
		"/api/v1/scoring",
		"/api/v1/health",
		"/api/v1/openapi.yaml",
		"/api/v1/stream",
		"/api/v1/findings",
		"/api/v1/runs",
		"/api/v1/triage",
	} {
		if !strings.Contains(body, p+":") {
			t.Errorf("path %q missing from spec:\n%s", p, body)
		}
	}
}

func TestSpec_EnvelopeSchemaPresent(t *testing.T) {
	doc := openapi.Spec("1.0.0")
	b, _ := openapi.Marshal(doc)
	body := string(b)
	if !strings.Contains(body, "components:") || !strings.Contains(body, "Envelope:") {
		t.Fatalf("components.schemas.Envelope missing:\n%s", body)
	}
	if !strings.Contains(body, "Plugin:") {
		t.Fatalf("components.schemas.Plugin missing")
	}
}

func TestSpec_VersionInjection(t *testing.T) {
	d1 := openapi.Spec("9.9.9")
	b1, _ := openapi.Marshal(d1)
	if !strings.Contains(string(b1), "version: 9.9.9") {
		t.Fatalf("injected version not found:\n%s", string(b1))
	}
	d2 := openapi.Spec("")
	b2, _ := openapi.Marshal(d2)
	if !strings.Contains(string(b2), "0.1.0-dev") {
		t.Fatalf("default version not applied")
	}
}

func TestMarshal_DescribesResponses(t *testing.T) {
	doc := openapi.Spec("t")
	b, _ := openapi.Marshal(doc)
	body := string(b)
	if !strings.Contains(body, "$ref: '#/components/schemas/Envelope'") &&
		!strings.Contains(body, "$ref: \"#/components/schemas/Envelope\"") {
		t.Fatalf("Envelope $ref missing:\n%s", body)
	}
}
