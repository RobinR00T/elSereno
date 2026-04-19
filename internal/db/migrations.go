package db

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
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

// MigrateUp applies every pending migration.
func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, func(db *sql.DB) error { return goose.UpContext(ctx, db, MigrationDir) })
}

// MigrateDown rolls back the most recent migration.
func MigrateDown(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, func(db *sql.DB) error { return goose.DownContext(ctx, db, MigrationDir) })
}

// MigrateStatus prints migration state via the configured goose logger.
func MigrateStatus(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, func(db *sql.DB) error { return goose.StatusContext(ctx, db, MigrationDir) })
}

// Verify checks that goose can reach the database and read the
// version. Returns an error on connectivity or schema-drift problems.
func Verify(ctx context.Context, pool *pgxpool.Pool) error {
	return run(ctx, pool, func(db *sql.DB) error {
		_, err := goose.EnsureDBVersionContext(ctx, db)
		if err != nil {
			return fmt.Errorf("db: ensure version: %w", err)
		}
		return nil
	})
}

func run(_ context.Context, pool *pgxpool.Pool, fn func(*sql.DB) error) error {
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
	goose.SetLogger(&bufferedLogger{buf: &bytes.Buffer{}})

	sqlDB := stdlib.OpenDBFromPool(pool)
	defer func() { _ = sqlDB.Close() }()

	return fn(sqlDB)
}

// bufferedLogger keeps goose quiet in-process; the CLI already prints
// progress via cobra. It implements goose.Logger.
type bufferedLogger struct{ buf *bytes.Buffer }

func (l *bufferedLogger) Fatalf(format string, v ...any) {
	fmt.Fprintf(l.buf, "FATAL: "+format+"\n", v...)
}
func (l *bufferedLogger) Printf(format string, v ...any) {
	fmt.Fprintf(l.buf, format+"\n", v...)
}
