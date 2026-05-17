package config

import "time"

// Config is the top-level runtime configuration for ElSereno. Every
// field has a default (Defaults()); YAML loading (F1) calls Validate()
// on top. Unknown YAML keys are rejected with ErrUnknownConfigField.
type Config struct {
	Retention RetentionConfig `koanf:"retention" yaml:"retention"`
	Evidence  EvidenceConfig  `koanf:"evidence"  yaml:"evidence"`
	Scanner   ScannerConfig   `koanf:"scanner"   yaml:"scanner"`
	Log       LogConfig       `koanf:"log"       yaml:"log"`
	Shutdown  ShutdownConfig  `koanf:"shutdown"  yaml:"shutdown"`
	Doctor    DoctorConfig    `koanf:"doctor"    yaml:"doctor"`
	Database  DatabaseConfig  `koanf:"database"  yaml:"database"`
	Web       WebConfig       `koanf:"web"       yaml:"web"`
	ReadyZ    ReadyZConfig    `koanf:"readyz"    yaml:"readyz"`
	Exec      ExecConfig      `koanf:"exec"      yaml:"exec"`
	Outbox    OutboxConfig    `koanf:"outbox"    yaml:"outbox"`
	// Auth (v2.43+) holds OIDC bearer-token validation
	// settings. When empty, the web layer falls back to
	// X-Operator dev-mode behaviour (the v1.58 baseline).
	Auth AuthConfig `koanf:"auth" yaml:"auth"`
}

// AuthConfig (v2.43+) groups the auth-related runtime
// settings. Currently only OIDC; future modes (mTLS, basic
// auth for air-gapped deployments) can extend this stanza
// without bumping the YAML schema for everyone.
type AuthConfig struct {
	OIDC OIDCConfig `koanf:"oidc" yaml:"oidc"`
}

// OIDCConfig declares the bearer-token validator settings.
// Empty issuer/audience/jwks_url → OIDC enforcement off
// (back-compat dev mode; X-Operator header is honoured).
//
// All three URLs are validated for shape at Validate() time:
//   - issuer: full URL with scheme + host (https:// strongly
//     recommended; http:// allowed for loopback dev only).
//   - audience: opaque string matched against the JWT `aud`.
//   - jwks_url: full URL to the JWKS endpoint (typically
//     <issuer>/.well-known/jwks.json or similar).
//
// clock_skew defaults to 60s when zero.
type OIDCConfig struct {
	Issuer    string        `koanf:"issuer"     yaml:"issuer"`
	Audience  string        `koanf:"audience"   yaml:"audience"`
	JWKSURL   string        `koanf:"jwks_url"   yaml:"jwks_url"`
	ClockSkew time.Duration `koanf:"clock_skew" yaml:"clock_skew"`
}

// Enabled reports whether OIDC enforcement is active. All
// three fields must be non-empty; partial config is treated
// as disabled to prevent footguns (e.g. issuer set but
// jwks_url forgotten silently passes everything).
func (o OIDCConfig) Enabled() bool {
	return o.Issuer != "" && o.Audience != "" && o.JWKSURL != ""
}

// RetentionConfig covers per-class retention in days. Evidence additionally
// follows the keep-if-referenced rule (a row is not deleted while any
// finding still references it).
type RetentionConfig struct {
	FindingsDays int `koanf:"findings_days" yaml:"findings_days"`
	EvidenceDays int `koanf:"evidence_days" yaml:"evidence_days"`
	RunsDays     int `koanf:"runs_days"     yaml:"runs_days"`
}

// EvidenceConfig bounds captured payloads.
type EvidenceConfig struct {
	MaxPayloadBytes int `koanf:"max_payload_bytes" yaml:"max_payload_bytes"`
}

// ScannerConfig caps concurrency.
type ScannerConfig struct {
	MaxConcurrentTargets int `koanf:"max_concurrent_targets"  yaml:"max_concurrent_targets"`
	MaxConcurrentPerHost int `koanf:"max_concurrent_per_host" yaml:"max_concurrent_per_host"`
}

// LogConfig routes structured logs.
type LogConfig struct {
	Level  string `koanf:"level"  yaml:"level"`
	Output string `koanf:"output" yaml:"output"`
}

// ShutdownConfig bounds the graceful drain.
type ShutdownConfig struct {
	DrainTimeout time.Duration `koanf:"drain_timeout" yaml:"drain_timeout"`
}

// DoctorConfig configures the doctor preflight.
type DoctorConfig struct {
	NTPServer string `koanf:"ntp_server" yaml:"ntp_server"`
}

// TLSRequired enumerates the three valid values of
// database.tls_required (ADR-021, PITF-022).
type TLSRequired string

// TLSRequired values.
const (
	// TLSAuto: TLS required unless the host is loopback.
	TLSAuto TLSRequired = "auto"
	// TLSAlways: TLS required regardless of host.
	TLSAlways TLSRequired = "always"
	// TLSDisable: TLS disabled; rejected at runtime for non-loopback hosts.
	TLSDisable TLSRequired = "disable"
)

// DatabaseConfig holds connection settings.
type DatabaseConfig struct {
	MaxConns    int         `koanf:"max_conns"    yaml:"max_conns"`
	TLSRequired TLSRequired `koanf:"tls_required" yaml:"tls_required"`
}

// WebConfig aggregates HTTP server settings.
type WebConfig struct {
	TokenTTLDays            int           `koanf:"token_ttl_days"             yaml:"token_ttl_days"`
	TokenGenerationCacheTTL time.Duration `koanf:"token_generation_cache_ttl" yaml:"token_generation_cache_ttl"`
	RateLimitPerMinIP       int           `koanf:"rate_limit_per_min_ip"      yaml:"rate_limit_per_min_ip"`
	RateLimitPerMinToken    int           `koanf:"rate_limit_per_min_token"   yaml:"rate_limit_per_min_token"`
	MaxBodyBytes            int           `koanf:"max_body_bytes"             yaml:"max_body_bytes"`
	ReadHeaderTimeout       time.Duration `koanf:"read_header_timeout"        yaml:"read_header_timeout"`
	ReadTimeout             time.Duration `koanf:"read_timeout"               yaml:"read_timeout"`
	WriteTimeout            time.Duration `koanf:"write_timeout"              yaml:"write_timeout"`
	IdleTimeout             time.Duration `koanf:"idle_timeout"               yaml:"idle_timeout"`
}

// ReadyZConfig bounds expensive readiness probes.
type ReadyZConfig struct {
	AuditTailEntries int `koanf:"audit_tail_entries" yaml:"audit_tail_entries"`
}

// ExecConfig lists allowed paths for SafeCommand.
type ExecConfig struct {
	AllowedPaths []string `koanf:"allowed_paths" yaml:"allowed_paths"`
}

// OutboxConfig bounds retries.
type OutboxConfig struct {
	MaxAttempts int `koanf:"max_attempts" yaml:"max_attempts"`
}

// Defaults returns the canonical default configuration (see sections 7
// and 9 of the project brief).
func Defaults() Config {
	return Config{
		Evidence: EvidenceConfig{MaxPayloadBytes: 16384},
		Scanner: ScannerConfig{
			MaxConcurrentTargets: 100,
			MaxConcurrentPerHost: 1,
		},
		Log:      LogConfig{Level: "info", Output: "stderr"},
		Shutdown: ShutdownConfig{DrainTimeout: 10 * time.Second},
		Database: DatabaseConfig{MaxConns: 10, TLSRequired: TLSAuto},
		Web: WebConfig{
			TokenTTLDays:            30,
			TokenGenerationCacheTTL: 5 * time.Second,
			RateLimitPerMinIP:       100,
			RateLimitPerMinToken:    300,
			MaxBodyBytes:            1 << 20,
			ReadHeaderTimeout:       5 * time.Second,
			ReadTimeout:             30 * time.Second,
			WriteTimeout:            30 * time.Second,
			IdleTimeout:             120 * time.Second,
		},
		ReadyZ: ReadyZConfig{AuditTailEntries: 100},
		Exec: ExecConfig{
			AllowedPaths: []string{"/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"},
		},
		Outbox: OutboxConfig{MaxAttempts: 10},
	}
}
