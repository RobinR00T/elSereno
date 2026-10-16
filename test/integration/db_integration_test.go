//go:build integration

// Package integration_test exercises ElSereno against a live Postgres
// from simulators/docker-compose.test.yml. Run with `make
// test-integration-db`, or:
//
//	docker compose -f simulators/docker-compose.test.yml up -d --wait db
//	DATABASE_URL='postgres://elsereno@127.0.0.1:5434/elsereno?sslmode=disable' \
//	  go test -tags integration -count=1 ./test/integration/...
//
// Without DATABASE_URL the migration test skips (`make
// test-integration`); the CI integration job sets it, so there it runs.
package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/config"
	"local/elsereno/internal/db"
	"local/elsereno/internal/scanorch"
)

func dsn() string {
	if v := os.Getenv("DATABASE_URL"); v != "" {
		return v
	}
	// Matches docker-compose.test.yml port.
	return "postgres://elsereno@127.0.0.1:5434/elsereno?sslmode=disable"
}

func TestMigrateAndVerify(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" && os.Getenv("ELSERENO_TEST_DB") == "" {
		t.Skip("set DATABASE_URL or ELSERENO_TEST_DB to enable")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.New(ctx, dsn(), config.TLSAuto, 4)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	defer pool.Close()

	if err := db.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	if err := db.Verify(ctx, pool); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestCronScheduleInsert: a cron schedule stores interval_seconds = 0.
// Migration 00008 meant to drop the v1.71 interval CHECK by matching
// "BETWEEN" in its definition, but PostgreSQL stores BETWEEN as >= AND
// <=, so the old CHECK survived and rejected every cron schedule;
// 00021 drops it (PITF-086).
func TestCronScheduleInsert(t *testing.T) {
	if os.Getenv("DATABASE_URL") == "" && os.Getenv("ELSERENO_TEST_DB") == "" {
		t.Skip("set DATABASE_URL or ELSERENO_TEST_DB to enable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := db.New(ctx, dsn(), config.TLSAuto, 4)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	defer pool.Close()
	if err := db.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'scan_schedules'::regclass AND contype = 'c'`)
	if err != nil {
		t.Fatalf("list CHECK constraints: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, def string
		if err := rows.Scan(&name, &def); err != nil {
			t.Fatalf("scan: %v", err)
		}
		t.Logf("scan_schedules CHECK %s: %s", name, def)
		if strings.Contains(def, "interval_seconds") && strings.Contains(def, "604800") && !strings.Contains(def, "cron_expr") {
			t.Errorf("interval-only CHECK %s survived the migrations: %s", name, def)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list CHECK constraints: %v", err)
	}
	rows.Close()

	store := scanorch.NewDBScheduleStore(pool)
	s, err := store.Create(ctx, scanorch.CreateScheduleRequest{
		Name:     "integration-cron-" + time.Now().UTC().Format("20060102T150405.000000000"),
		Template: scanorch.SubmitRequest{Input: "list:127.0.0.1"},
		CronExpr: "*/5 * * * *",
	}, "integration-test")
	if err != nil {
		t.Fatalf("creating a cron schedule: %v", err)
	}
	if err := store.Delete(ctx, s.ID); err != nil {
		t.Fatalf("deleting the cron schedule: %v", err)
	}
}
