package config

import "time"

// Config is the top-level runtime configuration for ElSereno. Every
// field has a default (Defaults()); YAML loading (F1) calls Validate()
// on top. Unknown YAML keys are rejected with ErrUnknownConfigField.
type Config struct {
	Retention RetentionConfig `yaml:"retention" koanf:"retention"`
	Evidence  EvidenceConfig  `yaml:"evidence" koanf:"evidence"`
	Scanner   ScannerConfig   `yaml:"scanner" koanf:"scanner"`
	Log       LogConfig       `yaml:"log" koanf:"log"`
	Shutdown  ShutdownConfig  `yaml:"shutdown" koanf:"shutdown"`
	Doctor    DoctorConfig    `yaml:"doctor" koanf:"doctor"`
	Database  DatabaseConfig  `yaml:"database" koanf:"database"`
	Web       WebConfig       `yaml:"web" koanf:"web"`
	ReadyZ    ReadyZConfig    `yaml:"readyz" koanf:"readyz"`
	Exec      ExecConfig      `yaml:"exec" koanf:"exec"`
	Outbox    OutboxConfig    `yaml:"outbox" koanf:"outbox"`
}

// RetentionConfig covers per-class retention in days. Evidence additionally
// follows the keep-if-referenced rule (a row is not deleted while any
// finding still references it).
type RetentionConfig struct {
	FindingsDays int `yaml:"findings_days" koanf:"findings_days"`
	EvidenceDays int `yaml:"evidence_days" koanf:"evidence_days"`
	RunsDays     int `yaml:"runs_days" koanf:"runs_days"`
}

// EvidenceConfig bounds captured payloads.
type EvidenceConfig struct {
	MaxPayloadBytes int `yaml:"max_payload_bytes" koanf:"max_payload_bytes"`
}

// ScannerConfig caps concurrency.
type ScannerConfig struct {
	MaxConcurrentTargets int `yaml:"max_concurrent_targets" koanf:"max_concurrent_targets"`
	MaxConcurrentPerHost int `yaml:"max_concurrent_per_host" koanf:"max_concurrent_per_host"`
}

// LogConfig routes structured logs.
type LogConfig struct {
	Level  string `yaml:"level" koanf:"level"`
	Output string `yaml:"output" koanf:"output"`
}

// ShutdownConfig bounds the graceful drain.
type ShutdownConfig struct {
	DrainTimeout time.Duration `yaml:"drain_timeout" koanf:"drain_timeout"`
}

// DoctorConfig configures the doctor preflight.
type DoctorConfig struct {
	NTPServer string `yaml:"ntp_server" koanf:"ntp_server"`
}

// TLSRequired enumerates the three valid values of
// database.tls_required (ADR-021, PITF-022).
type TLSRequired string

const (
	TLSAuto    TLSRequired = "auto"
	TLSAlways  TLSRequired = "always"
	TLSDisable TLSRequired = "disable"
)

// DatabaseConfig holds connection settings.
type DatabaseConfig struct {
	MaxConns    int         `yaml:"max_conns" koanf:"max_conns"`
	TLSRequired TLSRequired `yaml:"tls_required" koanf:"tls_required"`
}

// WebConfig aggregates HTTP server settings.
type WebConfig struct {
	TokenTTLDays              int           `yaml:"token_ttl_days" koanf:"token_ttl_days"`
	TokenGenerationCacheTTL   time.Duration `yaml:"token_generation_cache_ttl" koanf:"token_generation_cache_ttl"`
	RateLimitPerMinIP         int           `yaml:"rate_limit_per_min_ip" koanf:"rate_limit_per_min_ip"`
	RateLimitPerMinToken      int           `yaml:"rate_limit_per_min_token" koanf:"rate_limit_per_min_token"`
	MaxBodyBytes              int           `yaml:"max_body_bytes" koanf:"max_body_bytes"`
	ReadHeaderTimeout         time.Duration `yaml:"read_header_timeout" koanf:"read_header_timeout"`
	ReadTimeout               time.Duration `yaml:"read_timeout" koanf:"read_timeout"`
	WriteTimeout              time.Duration `yaml:"write_timeout" koanf:"write_timeout"`
	IdleTimeout               time.Duration `yaml:"idle_timeout" koanf:"idle_timeout"`
}

// ReadyZConfig bounds expensive readiness probes.
type ReadyZConfig struct {
	AuditTailEntries int `yaml:"audit_tail_entries" koanf:"audit_tail_entries"`
}

// ExecConfig lists allowed paths for SafeCommand.
type ExecConfig struct {
	AllowedPaths []string `yaml:"allowed_paths" koanf:"allowed_paths"`
}

// OutboxConfig bounds retries.
type OutboxConfig struct {
	MaxAttempts int `yaml:"max_attempts" koanf:"max_attempts"`
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
