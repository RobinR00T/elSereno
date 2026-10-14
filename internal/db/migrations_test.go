package db

import (
	"testing"

	"github.com/pressly/goose/v3"
)

// TestMigrationVersionsUnique: goose panics ("duplicate version")
// while collecting migrations when two files share a version, before
// touching the database, so every `elsereno db migrate` command dies.
// From 2026-09-22 to 2026-10-14 two files were version 5 (PITF-084).
func TestMigrationVersionsUnique(t *testing.T) {
	entries, err := migrationsFS.ReadDir(MigrationDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]string{}
	for _, e := range entries {
		v, err := goose.NumericComponent(e.Name())
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if prev, dup := seen[v]; dup {
			t.Fatalf("migration version %d used twice: %s and %s", v, prev, e.Name())
		}
		seen[v] = e.Name()
	}
}

// TestMigrationsCollect: goose itself collects the embedded set, without
// a database, as versions 1..N with no gap.
func TestMigrationsCollect(t *testing.T) {
	goose.SetBaseFS(migrationsFS)
	t.Cleanup(func() { goose.SetBaseFS(nil) })
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("goose panicked collecting migrations: %v", r)
		}
	}()
	ms, err := goose.CollectMigrations(MigrationDir, 0, goose.MaxVersion)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range ms {
		if m.Version != int64(i+1) {
			t.Fatalf("migration %d has version %d (%s), want %d", i, m.Version, m.Source, i+1)
		}
	}
}
