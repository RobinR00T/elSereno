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
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/db"
	"local/elsereno/internal/repo"
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

// TestRunWriterRoundTrip: a run recorded with RunWriter shows up through
// the read side the dashboard uses (ListRuns, ListFindings), with the
// same target reused for a second finding (PITF-094).
func TestRunWriterRoundTrip(t *testing.T) {
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

	w := repo.NewRunWriter(pool)
	runID, err := w.StartRun(ctx, "integration-test")
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	addr := netip.MustParseAddr("192.0.2.77")
	var targets []string
	for _, proto := range []string{"modbus", "banner"} {
		f, err := w.RecordFinding(ctx, runID, core.Finding{Protocol: proto, Severity: core.SeverityMedium, Score: 50}, addr, 502)
		if err != nil {
			t.Fatalf("RecordFinding %s: %v", proto, err)
		}
		targets = append(targets, string(f.TargetID))
	}
	if targets[0] != targets[1] {
		t.Fatalf("same address:port got two targets: %v", targets)
	}
	if err := w.FinishRun(ctx, runID, "completed"); err != nil {
		t.Fatalf("FinishRun: %v", err)
	}

	found, err := repo.ListFindings(ctx, pool, repo.FindingsQuery{RunID: runID})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("ListFindings(run) = %d findings, want 2", len(found))
	}
	runs, err := repo.ListRuns(ctx, pool, repo.RunsQuery{Status: "completed", Limit: 500})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	seen := false
	for _, r := range runs {
		if r.ID == runID {
			seen = true
			if r.Findings != 2 {
				t.Errorf("run lists %d findings, want 2", r.Findings)
			}
		}
	}
	if !seen {
		t.Fatalf("run %s not in ListRuns", runID)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM findings WHERE run_id = $1", runID); err != nil {
		t.Fatalf("cleanup findings: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM runs WHERE id = $1", runID); err != nil {
		t.Fatalf("cleanup run: %v", err)
	}
}

// TestScheduleCreateDisabled: a schedule created with StartDisabled is
// stored disabled in the same INSERT, so no scheduler tick can fire it
// (PITF-094; the import path relies on it).
func TestScheduleCreateDisabled(t *testing.T) {
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
	store := scanorch.NewDBScheduleStore(pool)
	s, err := store.Create(ctx, scanorch.CreateScheduleRequest{
		Name:            "integration-disabled-" + time.Now().UTC().Format("20060102T150405.000000000"),
		Template:        scanorch.SubmitRequest{Input: "list:127.0.0.1"},
		IntervalSeconds: 60,
		StartDisabled:   true,
	}, "integration-test")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer func() { _ = store.Delete(ctx, s.ID) }()
	got, err := store.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Enabled {
		t.Fatal("schedule created with StartDisabled is enabled in the database")
	}
}
