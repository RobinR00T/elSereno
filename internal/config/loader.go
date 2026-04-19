package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// LookupOrder is the documented precedence for config discovery (brief
// section 7 F0 item 6). Loader.Discover picks the first path that
// exists, in this order.
type LookupOrder struct {
	// Explicit is the value passed via --config; empty means "use the
	// rest of the order". When non-empty and the file does not exist,
	// Discover returns an error (explicit paths are not fallback points).
	Explicit string

	// Env is the value of $ELSERENO_CONFIG; ignored when Explicit is set.
	Env string

	// HomeDir is the user's home directory (os.UserHomeDir). Allowed to
	// be empty; lookup skips home-prefixed paths in that case.
	HomeDir string

	// XDG is the value of $XDG_CONFIG_HOME. When empty, fall back to the
	// standard $HOME/.config path.
	XDG string

	// CWD is the current working directory; Discover appends
	// "./elsereno.yaml" last.
	CWD string
}

// Discover returns the first existing path, the empty string if none
// exists, or an error if Explicit was set and does not exist.
func (l LookupOrder) Discover() (string, error) {
	if l.Explicit != "" {
		if _, err := os.Stat(l.Explicit); err != nil {
			return "", fmt.Errorf("%w: --config %q: %w", ErrInvalidConfig, l.Explicit, err)
		}
		return l.Explicit, nil
	}

	var candidates []string
	if l.Env != "" {
		candidates = append(candidates, l.Env)
	}
	if l.XDG != "" {
		candidates = append(candidates, filepath.Join(l.XDG, "elsereno", "elsereno.yaml"))
	} else if l.HomeDir != "" {
		candidates = append(candidates, filepath.Join(l.HomeDir, ".config", "elsereno", "elsereno.yaml"))
	}
	if l.HomeDir != "" {
		candidates = append(candidates, filepath.Join(l.HomeDir, ".config", "elsereno", "elsereno.yaml"))
		candidates = append(candidates, filepath.Join(l.HomeDir, ".elsereno", "elsereno.yaml"))
	}
	if l.CWD != "" {
		candidates = append(candidates, filepath.Join(l.CWD, "elsereno.yaml"))
	}

	seen := make(map[string]struct{})
	for _, c := range candidates {
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", nil
}

// Loader wires koanf for discovery, layering, and unknown-field
// rejection. It is safe for single-shot use; callers that need a
// reload must construct a new instance.
type Loader struct {
	Order    LookupOrder
	validate *validator.Validate
}

// NewLoader constructs a Loader ready for Load().
func NewLoader(order LookupOrder) *Loader {
	return &Loader{
		Order:    order,
		validate: validator.New(validator.WithRequiredStructEnabled()),
	}
}

// Load reads config from the discovered file (if any), merges on top of
// Defaults(), rejects unknown keys, and runs validator. Returns an
// empty string for Path when no file was discovered.
func (l *Loader) Load(ctx context.Context) (cfg Config, path string, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = ctx // reserved for future remote-source providers.

	cfg = Defaults()

	path, err = l.Order.Discover()
	if err != nil {
		return cfg, "", err
	}

	k := koanf.NewWithConf(koanf.Conf{Delim: ".", StrictMerge: true})

	// Defaults first (flat map path → value).
	defaultsMap, err := structToMap(Defaults())
	if err != nil {
		return cfg, "", fmt.Errorf("%w: defaults: %w", ErrInvalidConfig, err)
	}
	if err := k.Load(confmap.Provider(defaultsMap, "."), nil); err != nil {
		return cfg, "", fmt.Errorf("%w: load defaults: %w", ErrInvalidConfig, err)
	}

	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return cfg, path, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, path, err)
		}
	}

	// Reject unknown keys by comparing the flattened key set against
	// the declared struct tags.
	if err := rejectUnknown(k.All(), cfg); err != nil {
		return cfg, path, err
	}

	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag:       "koanf",
		FlatPaths: false,
	}); err != nil {
		return cfg, path, fmt.Errorf("%w: unmarshal: %w", ErrInvalidConfig, err)
	}

	if err := l.validate.Struct(&cfg); err != nil {
		return cfg, path, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	if err := validateDatabaseTLS(cfg.Database.TLSRequired); err != nil {
		return cfg, path, err
	}

	return cfg, path, nil
}

// validateDatabaseTLS enforces the enum (ADR-021, PITF-022).
func validateDatabaseTLS(v TLSRequired) error {
	switch v {
	case TLSAuto, TLSAlways, TLSDisable:
		return nil
	default:
		return fmt.Errorf("%w: database.tls_required=%q not in {auto, always, disable}", ErrInvalidConfig, v)
	}
}

// rejectUnknown compares every key seen by koanf against the declared
// struct tag set and returns ErrUnknownConfigField on the first mismatch.
func rejectUnknown(all map[string]any, cfg Config) error {
	known := collectTagPaths("", cfg)
	for key := range all {
		// Accept any prefix-equal match; deeper structures produce
		// dotted keys like "web.token_ttl_days" and we want those too.
		if _, ok := known[key]; ok {
			continue
		}
		// Also accept parent keys (koanf emits both "web" and
		// "web.token_ttl_days"; only the leaf needs to be registered).
		if isAncestorOf(known, key) {
			continue
		}
		return fmt.Errorf("%w: %s", ErrUnknownConfigField, key)
	}
	return nil
}

func isAncestorOf(known map[string]struct{}, key string) bool {
	prefix := key + "."
	for k := range known {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}
