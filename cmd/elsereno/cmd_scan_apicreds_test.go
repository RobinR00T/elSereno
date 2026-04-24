package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCredsTempYAML(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.yaml")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write creds: %v", err)
	}
	return path
}

func TestLoadAPICreds_Happy(t *testing.T) {
	p := writeCredsTempYAML(t, `
shodan:
  key: shodan-key
censys:
  id: censys-id
  secret: censys-secret
fofa:
  email: user@example.com
  key: fofa-key
zoomeye:
  key: zoomeye-key
`, 0o600)
	got, err := loadAPICreds(p)
	if err != nil {
		t.Fatalf("loadAPICreds: %v", err)
	}
	if got.Shodan.Key != "shodan-key" {
		t.Errorf("Shodan.Key=%q", got.Shodan.Key)
	}
	if got.Censys.ID != "censys-id" || got.Censys.Secret != "censys-secret" {
		t.Errorf("Censys=%+v", got.Censys)
	}
	if got.FOFA.Email != "user@example.com" || got.FOFA.Key != "fofa-key" {
		t.Errorf("FOFA=%+v", got.FOFA)
	}
	if got.ZoomEye.Key != "zoomeye-key" {
		t.Errorf("ZoomEye.Key=%q", got.ZoomEye.Key)
	}
}

func TestLoadAPICreds_RejectsWorldReadable(t *testing.T) {
	p := writeCredsTempYAML(t, `shodan: {key: x}`, 0o644)
	_, err := loadAPICreds(p)
	if err == nil {
		t.Fatal("expected perms error for world-readable file")
	}
	if !strings.Contains(err.Error(), "must be 0600") {
		t.Errorf("error should mention 0600, got: %v", err)
	}
}

func TestLoadAPICreds_RejectsGroupReadable(t *testing.T) {
	p := writeCredsTempYAML(t, `shodan: {key: x}`, 0o640)
	_, err := loadAPICreds(p)
	if err == nil {
		t.Fatal("expected perms error for group-readable file")
	}
}

func TestLoadAPICreds_MissingFile(t *testing.T) {
	_, err := loadAPICreds("/tmp/does-not-exist-elsereno-creds-test.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadAPICreds_UnknownField(t *testing.T) {
	p := writeCredsTempYAML(t, `
unknown: foo
shodan:
  key: x
`, 0o600)
	_, err := loadAPICreds(p)
	if err == nil {
		t.Fatal("expected error on unknown field (KnownFields strict)")
	}
}

// readTargetsFromProvider end-to-end errors — each provider
// surfaces "missing <field>" when the creds block is incomplete.

func TestReadTargetsFromProvider_ErrNoCreds(t *testing.T) {
	_, err := readTargetsFromProvider(context.Background(), "shodan", "port:502", "")
	if !errors.Is(err, errAPICredsNotSet) {
		t.Fatalf("got %v, want errAPICredsNotSet", err)
	}
}

func TestReadTargetsFromProvider_EmptyQuery(t *testing.T) {
	_, err := readTargetsFromProvider(context.Background(), "fofa", "", "/tmp/whatever.yaml")
	if err == nil {
		t.Fatal("expected error for empty query")
	}
	if !strings.Contains(err.Error(), "query is empty") {
		t.Errorf("message should mention empty query: %v", err)
	}
}

func TestReadTargetsFromProvider_UnknownProvider(t *testing.T) {
	p := writeCredsTempYAML(t, `shodan: {key: x}`, 0o600)
	_, err := readTargetsFromProvider(context.Background(), "onyphe", "cat:ics", p)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown provider") {
		t.Errorf("message should mention unknown provider: %v", err)
	}
}

func TestReadTargetsFromProvider_MissingShodanKey(t *testing.T) {
	p := writeCredsTempYAML(t, `censys: {id: x, secret: y}`, 0o600)
	_, err := readTargetsFromProvider(context.Background(), "shodan", "port:502", p)
	if err == nil {
		t.Fatal("expected error for missing shodan.key")
	}
}

func TestReadTargetsFromProvider_MissingCensysSecret(t *testing.T) {
	p := writeCredsTempYAML(t, `censys: {id: only-id}`, 0o600)
	_, err := readTargetsFromProvider(context.Background(), "censys", "x", p)
	if err == nil {
		t.Fatal("expected error for missing censys.secret")
	}
}

func TestReadTargetsFromProvider_MissingFOFAEmail(t *testing.T) {
	p := writeCredsTempYAML(t, `fofa: {key: only-key}`, 0o600)
	_, err := readTargetsFromProvider(context.Background(), "fofa", "x", p)
	if err == nil {
		t.Fatal("expected error for missing fofa.email")
	}
}

func TestReadTargetsFromProvider_MissingZoomEyeKey(t *testing.T) {
	p := writeCredsTempYAML(t, `fofa: {email: e, key: k}`, 0o600)
	_, err := readTargetsFromProvider(context.Background(), "zoomeye", "x", p)
	if err == nil {
		t.Fatal("expected error for missing zoomeye.key")
	}
}
