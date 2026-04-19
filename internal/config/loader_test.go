package config_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/config"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "elsereno.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoader_DefaultsWhenNoFile(t *testing.T) {
	t.Parallel()
	l := config.NewLoader(config.LookupOrder{CWD: t.TempDir()})
	cfg, path, err := l.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if path != "" {
		t.Fatalf("expected no file, got %q", path)
	}
	if cfg.Web.TokenTTLDays != 30 {
		t.Fatalf("default TokenTTLDays = %d; want 30", cfg.Web.TokenTTLDays)
	}
	if cfg.Database.TLSRequired != config.TLSAuto {
		t.Fatalf("default TLSRequired = %q; want auto", cfg.Database.TLSRequired)
	}
}

func TestLoader_FileOverridesDefaults(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "web:\n  token_ttl_days: 7\n")
	l := config.NewLoader(config.LookupOrder{Explicit: p})
	cfg, got, err := l.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != p {
		t.Fatalf("path = %q, want %q", got, p)
	}
	if cfg.Web.TokenTTLDays != 7 {
		t.Fatalf("TokenTTLDays = %d; want 7", cfg.Web.TokenTTLDays)
	}
	if cfg.Web.RateLimitPerMinIP != 100 {
		t.Fatalf("RateLimitPerMinIP should keep default 100, got %d", cfg.Web.RateLimitPerMinIP)
	}
}

func TestLoader_RejectsUnknownField(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "web:\n  token_ttl_days: 7\n  nonsense_field: 1\n")
	l := config.NewLoader(config.LookupOrder{Explicit: p})
	_, _, err := l.Load(context.Background())
	if err == nil {
		t.Fatalf("expected ErrUnknownConfigField")
	}
	if !errors.Is(err, config.ErrUnknownConfigField) {
		t.Fatalf("got %v, want ErrUnknownConfigField", err)
	}
}

func TestLoader_RejectsUnknownTopLevel(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "bogus_section:\n  x: 1\n")
	l := config.NewLoader(config.LookupOrder{Explicit: p})
	_, _, err := l.Load(context.Background())
	if !errors.Is(err, config.ErrUnknownConfigField) {
		t.Fatalf("got %v, want ErrUnknownConfigField", err)
	}
}

func TestLoader_RejectsInvalidTLSEnum(t *testing.T) {
	t.Parallel()
	p := writeTemp(t, "database:\n  tls_required: maybe\n")
	l := config.NewLoader(config.LookupOrder{Explicit: p})
	_, _, err := l.Load(context.Background())
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("got %v, want ErrInvalidConfig", err)
	}
}

func TestLoader_ExplicitPathMissing(t *testing.T) {
	t.Parallel()
	l := config.NewLoader(config.LookupOrder{Explicit: "/does/not/exist"})
	_, _, err := l.Load(context.Background())
	if !errors.Is(err, config.ErrInvalidConfig) {
		t.Fatalf("got %v, want ErrInvalidConfig", err)
	}
}
