package db

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNoMigrations signals that the embedded FS has no files; primarily
// useful in tests.
var ErrNoMigrations = errors.New("db: no migrations embedded")

// MigrationDir is the directory (within the embedded FS) that goose
// scans. Kept exported so `elsereno db status` can surface it.
const MigrationDir = "migrations"

// MigrateUp applies every pending migration. The caller owns pool
// lifecycle.
func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, "up")
}

// MigrateDown rolls back the most recent migration.
func MigrateDown(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, "down")
}

// MigrateStatus prints the migration state via the goose provider.
func MigrateStatus(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, "status")
}

func run(ctx context.Context, pool *pgxpool.Pool, action string) error {
	entries, err := migrationsFS.ReadDir(MigrationDir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoMigrations, err)
	}
	if len(entries) == 0 {
		return ErrNoMigrations
	}

	goose.SetBaseFS(migrationsFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("db: set dialect: %w", err)
	}

	// goose expects *sql.DB; we bridge via stdlib's database/sql driver
	// wrapped around the pgxpool. In F1 chunk 2 we wire
	// github.com/jackc/pgx/v5/stdlib.OpenDBFromPool; the placeholder
	// below returns a clear message.
	_ = pool
	_ = ctx
	return fmt.Errorf("db: migration %q wiring pending in F1 chunk 2 (requires pgx stdlib bridge)", action)
}
