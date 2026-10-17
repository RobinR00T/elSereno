package config_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"local/elsereno/internal/config"
)

// TestLoader_ShowOutputLoadsBack: the defaults written as YAML (what
// `config show` prints, durations as "10s") load back to the same
// config. Until 2026-10-17 any file with a duration or a list failed
// with "incorrect types" (PITF-096).
func TestLoader_ShowOutputLoadsBack(t *testing.T) {
	b, err := yaml.Marshal(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "elsereno.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.NewLoader(config.LookupOrder{Explicit: p}).Load(context.Background())
	if err != nil {
		t.Fatalf("Load(show output): %v\n%s", err, b)
	}
	if !reflect.DeepEqual(cfg, config.Defaults()) {
		t.Fatalf("round trip changed the config:\n got %+v\nwant %+v", cfg, config.Defaults())
	}
}

// TestLoader_DurationsAndListsFromFile: durations, an enum and a list
// in a file override the defaults.
func TestLoader_DurationsAndListsFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "elsereno.yaml")
	body := "web:\n  read_timeout: 45s\nshutdown:\n  drain_timeout: 1m\ndatabase:\n  tls_required: always\nexec:\n  allowed_paths: [/usr/bin]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.NewLoader(config.LookupOrder{Explicit: p}).Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Web.ReadTimeout != 45*time.Second || cfg.Shutdown.DrainTimeout != time.Minute ||
		cfg.Database.TLSRequired != config.TLSAlways || !reflect.DeepEqual(cfg.Exec.AllowedPaths, []string{"/usr/bin"}) {
		t.Fatalf("file values not applied: %+v", cfg)
	}
}

// TestLoader_RejectsNegativeDuration: net/http reads a timeout <= 0 as
// no limit, so a negative one is refused rather than leaving serve open
// to slow clients (audit of PITF-096).
func TestLoader_RejectsNegativeDuration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "elsereno.yaml")
	if err := os.WriteFile(p, []byte("web:\n  read_header_timeout: -1s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := config.NewLoader(config.LookupOrder{Explicit: p}).Load(context.Background())
	if !errors.Is(err, config.ErrInvalidConfig) || !strings.Contains(err.Error(), "web.read_header_timeout") {
		t.Fatalf("err = %v, want ErrInvalidConfig naming web.read_header_timeout", err)
	}
}
