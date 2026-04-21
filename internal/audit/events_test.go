package audit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"local/elsereno/internal/audit"
)

// TestEventTypesMatchMigration asserts that the Go event-type constants
// stay in sync with the SQL CHECK enumeration walked across all
// migrations in order (00001, 00002, …). Each migration may
// replace the CHECK; the LAST one wins. This is the source of
// truth per ADR-023 / PITF-030.
func TestEventTypesMatchMigration(t *testing.T) {
	// Authoritative path: goose embeds `internal/db/migrations/*.sql`
	// (see internal/db/migrations.go). The repo-root `migrations/`
	// directory is a legacy scaffold kept around for dev-time
	// tooling but is NOT what runs in production.
	matches, err := filepath.Glob("../db/migrations/*.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(matches) // numeric prefix keeps lexicographic order == apply order

	// Matches both:
	//   event_type TEXT NOT NULL CHECK (event_type IN ('a','b'))          -- inline (00001)
	//   ADD CONSTRAINT audit_log_event_type_check CHECK (event_type IN …) -- altered (00002+)
	re := regexp.MustCompile(`(?s)CHECK\s*\(event_type\s+IN\s*\(([^)]*)\)`)
	// Track the most recent Up-side CHECK block we found. The Down
	// side deliberately restores the pre-change enumeration and
	// would give a false "old" answer if we took the wrong half.
	var lastCheckBody string
	for _, path := range matches {
		b, err := os.ReadFile(path) //nolint:gosec // G304 — path under ../../migrations/
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		up := extractUpBlock(string(b))
		// Each migration may contain multiple CHECK blocks (e.g. a
		// DROP-then-ADD pair). Take the LAST match — that's the
		// final enumeration after the migration finishes.
		all := re.FindAllStringSubmatch(up, -1)
		if len(all) > 0 {
			lastCheckBody = all[len(all)-1][1]
		}
	}
	if lastCheckBody == "" {
		t.Fatal("no migration defines an audit_log event_type CHECK")
	}

	rawNames := regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(lastCheckBody, -1)
	got := make([]string, 0, len(rawNames))
	for _, n := range rawNames {
		got = append(got, n[1])
	}

	want := make([]string, 0, len(audit.AllEventTypes))
	for _, e := range audit.AllEventTypes {
		want = append(want, string(e))
	}

	sort.Strings(got)
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("drift between Go AllEventTypes and SQL CHECK:\n  go:  %v\n  sql: %v", want, got)
	}
}

// extractUpBlock returns the text between `-- +goose Up` and the
// first `-- +goose Down` marker so we don't accidentally read
// CHECK rewrites from the Down half.
func extractUpBlock(sql string) string {
	const upMarker = "-- +goose Up"
	const downMarker = "-- +goose Down"
	up := strings.Index(sql, upMarker)
	if up < 0 {
		return sql
	}
	tail := sql[up:]
	down := strings.Index(tail, downMarker)
	if down < 0 {
		return tail
	}
	return tail[:down]
}

func TestIsProtectedMetadata(t *testing.T) {
	protected := []audit.EventType{audit.EventGenesis, audit.EventChainRebase, audit.EventPurge}
	for _, e := range protected {
		if !audit.IsProtectedMetadata(e) {
			t.Fatalf("expected %s to be protected", e)
		}
	}
	if audit.IsProtectedMetadata(audit.EventTokenRotate) {
		t.Fatalf("token_rotate must NOT be treated as protected")
	}
}
