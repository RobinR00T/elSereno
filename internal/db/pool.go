package db

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"local/elsereno/internal/config"
)

// ErrLoopbackRequired is returned when `database.tls_required=disable`
// is configured against a non-loopback host (ADR-021, PITF-022).
var ErrLoopbackRequired = errors.New("db: tls_required=disable only allowed against loopback hosts")

// New opens a pgx connection pool enforcing the ADR-021 TLS policy on
// top of the caller-provided DSN.
func New(ctx context.Context, dsn string, tls config.TLSRequired, maxConns int) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, fmt.Errorf("db: empty DSN")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse DSN: %w", err)
	}
	if maxConns > 0 {
		if maxConns > math.MaxInt32 {
			return nil, fmt.Errorf("db: max_conns=%d exceeds int32 max", maxConns)
		}
		cfg.MaxConns = int32(maxConns) // #nosec G115 -- bounded above
	}

	if err := applyTLSPolicy(cfg.ConnConfig, tls); err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: new pool: %w", err)
	}
	return pool, nil
}

// applyTLSPolicy inspects the host and the configured policy and
// adjusts pgx.ConnConfig.TLSConfig accordingly. The rules:
//
//   - disable on non-loopback -> ErrLoopbackRequired.
//   - always -> ensure TLS; set SSLMode=require via connection string.
//   - auto   -> if host is loopback, leave caller's choice alone; else
//     require TLS.
//   - disable on loopback -> leave caller's choice.
func applyTLSPolicy(cc *pgx.ConnConfig, tls config.TLSRequired) error {
	host := cc.Host
	loopback := host == "" || host == "127.0.0.1" || host == "::1" || host == "localhost"

	switch tls {
	case config.TLSDisable:
		if !loopback {
			return fmt.Errorf("%w: host=%q", ErrLoopbackRequired, host)
		}
		// TLSConfig left as-is; caller's DSN decides.
	case config.TLSAlways:
		if cc.TLSConfig == nil {
			return fmt.Errorf("db: tls_required=always but DSN has no sslmode")
		}
	case config.TLSAuto:
		if !loopback && cc.TLSConfig == nil {
			return fmt.Errorf("db: tls_required=auto and host=%q is not loopback; set sslmode=verify-full", host)
		}
	default:
		return fmt.Errorf("db: unknown tls_required=%q", tls)
	}
	return nil
}
