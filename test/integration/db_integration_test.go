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
	"testing"
	"time"

	"local/elsereno/internal/config"
	"local/elsereno/internal/db"
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
