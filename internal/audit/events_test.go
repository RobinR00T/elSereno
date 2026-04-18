package audit_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"local/elsereno/internal/audit"
)

// TestEventTypesMatchMigration asserts that the Go event-type constants
// stay in sync with the SQL CHECK enumeration in the 00001 migration.
// The migration is the source of truth (ADR-023, PITF-030).
func TestEventTypesMatchMigration(t *testing.T) {
	b, err := os.ReadFile("../../migrations/00001_initial.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	sql := string(b)

	// Extract the CHECK enumeration — the single-quoted strings inside
	// the event_type CHECK block.
	re := regexp.MustCompile(`(?s)event_type\s+TEXT\s+NOT\s+NULL\s+CHECK\s*\(event_type\s+IN\s*\(([^)]*)\)`)
	m := re.FindStringSubmatch(sql)
	if len(m) != 2 {
		t.Fatalf("could not locate event_type CHECK block in migration")
	}

	rawNames := regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(m[1], -1)
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
