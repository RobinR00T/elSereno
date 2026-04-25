package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"local/elsereno/internal/core"
	"local/elsereno/internal/inputs/censys"
	"local/elsereno/internal/inputs/fofa"
	"local/elsereno/internal/inputs/internetdb"
	"local/elsereno/internal/inputs/onyphe"
	"local/elsereno/internal/inputs/shodan"
	"local/elsereno/internal/inputs/zoomeye"
)

// apiCreds is the YAML schema for --api-creds-file. Each
// provider carries its own auth block; only the block matching
// the --input <provider>:<query> prefix is consulted.
//
// Example YAML (0600 perms enforced at load time):
//
//	shodan:
//	  key: <shodan-api-key>
//	censys:
//	  id: <censys-api-id>
//	  secret: <censys-api-secret>
//	fofa:
//	  email: <fofa-email>
//	  key: <fofa-api-key>
//	zoomeye:
//	  key: <zoomeye-api-key>
type apiCreds struct {
	Shodan struct {
		Key string `yaml:"key"`
	} `yaml:"shodan"`
	Censys struct {
		ID     string `yaml:"id"`
		Secret string `yaml:"secret"`
	} `yaml:"censys"`
	FOFA struct {
		Email string `yaml:"email"`
		Key   string `yaml:"key"`
	} `yaml:"fofa"`
	ZoomEye struct {
		Key string `yaml:"key"`
	} `yaml:"zoomeye"`
	Onyphe struct {
		Key string `yaml:"key"`
	} `yaml:"onyphe"`
}

// loadAPICreds reads + parses the creds file. Enforces 0600
// perms (file must not be group- or world-readable) because
// API keys leak via `ls -l` + `ps e` otherwise.
func loadAPICreds(path string) (apiCreds, error) {
	var out apiCreds
	info, err := os.Stat(path)
	if err != nil {
		return out, fmt.Errorf("--api-creds-file %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return out, fmt.Errorf("--api-creds-file %s: permissions %o must be 0600 (chmod 600 %s)",
			path, info.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304 — path is operator-supplied; 0600 check above prevents world-readable leaks.
	if err != nil {
		return out, fmt.Errorf("--api-creds-file %s: %w", path, err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("--api-creds-file %s: parse: %w", path, err)
	}
	return out, nil
}

// errAPICredsNotSet is returned when the operator uses a
// provider input (e.g. --input shodan:…) but omits
// --api-creds-file. Caller surfaces the remediation hint.
//
// internetdb is excluded from this check — it requires no API
// key — so its readInternetDBTargets path bypasses creds load.
var errAPICredsNotSet = errors.New("--api-creds-file is required for provider inputs (shodan:, censys:, fofa:, zoomeye:, onyphe:)")

// readTargetsFromProvider dispatches `<provider>:<query>` to
// the matching input client. Provider is the prefix of the
// --input flag (before the colon); query is everything after.
//
// Rate limits are applied by the clients themselves (constructor
// takes a rps parameter; we pass 1 rps to avoid burning quota
// on the free tier).
func readTargetsFromProvider(ctx context.Context, provider, query, credsFile string) ([]core.Target, error) {
	if query == "" {
		return nil, fmt.Errorf("--input %s: query is empty (form: --input %s:<query>)", provider, provider)
	}
	// internetdb is the only no-key provider — bypass the
	// credentials file entirely.
	if provider == "internetdb" {
		return readInternetDBTargets(ctx, query)
	}
	if credsFile == "" {
		return nil, errAPICredsNotSet
	}
	creds, err := loadAPICreds(credsFile)
	if err != nil {
		return nil, err
	}
	switch provider {
	case "shodan":
		return readShodanTargets(ctx, creds, query)
	case "censys":
		return readCensysTargets(ctx, creds, query)
	case "fofa":
		return readFOFATargets(ctx, creds, query)
	case "zoomeye":
		return readZoomEyeTargets(ctx, creds, query)
	case "onyphe":
		return readOnypheTargets(ctx, creds, query)
	}
	return nil, fmt.Errorf("--input %s: unknown provider (known: shodan | censys | fofa | zoomeye | onyphe | internetdb)", provider)
}

// readInternetDBTargets dispatches `internetdb:<ip>` to the
// no-key Shodan InternetDB lookup. Single-IP for v1.12; bulk
// (file or stdin) is a v1.13+ follow-up.
func readInternetDBTargets(ctx context.Context, query string) ([]core.Target, error) {
	c := internetdb.New(0)
	return c.Lookup(ctx, query)
}

// providerTotalLimit is the default cap per --input call. v1.12
// chunk 8 enables pagination across all 5 providers; this cap
// keeps free-tier quota usage sane (each provider returns ~100/
// page, so 1000 hits = ~10 paginated requests). Operators
// wanting more raise the cap via the (future) --max-results
// flag — out of scope for chunk 8.
const providerTotalLimit = 1000

func readShodanTargets(ctx context.Context, creds apiCreds, query string) ([]core.Target, error) {
	if creds.Shodan.Key == "" {
		return nil, fmt.Errorf("shodan: missing `shodan.key` in --api-creds-file")
	}
	c, err := shodan.New(creds.Shodan.Key, 1)
	if err != nil {
		return nil, err
	}
	return c.SearchPaged(ctx, query, providerTotalLimit)
}

func readCensysTargets(ctx context.Context, creds apiCreds, query string) ([]core.Target, error) {
	if creds.Censys.ID == "" || creds.Censys.Secret == "" {
		return nil, fmt.Errorf("censys: missing `censys.id` or `censys.secret` in --api-creds-file")
	}
	c, err := censys.New(creds.Censys.ID, creds.Censys.Secret, 1)
	if err != nil {
		return nil, err
	}
	return c.SearchPaged(ctx, query, providerTotalLimit)
}

func readFOFATargets(ctx context.Context, creds apiCreds, query string) ([]core.Target, error) {
	if creds.FOFA.Email == "" || creds.FOFA.Key == "" {
		return nil, fmt.Errorf("fofa: missing `fofa.email` or `fofa.key` in --api-creds-file")
	}
	c, err := fofa.New(creds.FOFA.Email, creds.FOFA.Key, 1)
	if err != nil {
		return nil, err
	}
	return c.SearchPaged(ctx, query, providerTotalLimit)
}

func readZoomEyeTargets(ctx context.Context, creds apiCreds, query string) ([]core.Target, error) {
	if creds.ZoomEye.Key == "" {
		return nil, fmt.Errorf("zoomeye: missing `zoomeye.key` in --api-creds-file")
	}
	c, err := zoomeye.New(creds.ZoomEye.Key, 1)
	if err != nil {
		return nil, err
	}
	return c.SearchPaged(ctx, query, providerTotalLimit)
}

func readOnypheTargets(ctx context.Context, creds apiCreds, query string) ([]core.Target, error) {
	if creds.Onyphe.Key == "" {
		return nil, fmt.Errorf("onyphe: missing `onyphe.key` in --api-creds-file")
	}
	c, err := onyphe.New(creds.Onyphe.Key, 1)
	if err != nil {
		return nil, err
	}
	return c.SearchPaged(ctx, query, providerTotalLimit)
}
