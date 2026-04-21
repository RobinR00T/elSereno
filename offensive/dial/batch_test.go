//go:build offensive

package dial_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/scope"
	"local/elsereno/offensive/dial"
)

// openBatch wires an audit.FileWriter in a t.TempDir and returns a
// Batch ready to Run. The Writer is closed via t.Cleanup so the
// chain is flushed before assertions read the file.
func openBatch(t *testing.T, sc *scope.Scope) (*dial.Batch, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return &dial.Batch{
		Scope:  sc,
		Writer: w,
		Actor:  "ci",
	}, path
}

func TestBatchRun_ClassifiesEachNumber(t *testing.T) {
	b, _ := openBatch(t, nil)
	input := strings.NewReader(`# sample wardial input
112
5551234567
9999999999
`)
	res, err := b.Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("results = %d, want 3", len(res))
	}
	wantDecisions := []string{"short", "allow", "allow"}
	for i, want := range wantDecisions {
		if res[i].Decision != want {
			t.Errorf("res[%d].Decision = %q, want %q", i, res[i].Decision, want)
		}
	}
}

func TestBatchRun_ScopeBlocksPrefixMatches(t *testing.T) {
	sc := &scope.Scope{
		Dial: scope.DialDecl{BlockedNumbers: []string{"555"}},
	}
	b, _ := openBatch(t, sc)
	res, err := b.Run(context.Background(), strings.NewReader("5551234567\n4441234567\n"))
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Decision != "blocked" {
		t.Fatalf("555… should be scope-blocked, got %q", res[0].Decision)
	}
	if res[1].Decision != "allow" {
		t.Fatalf("444… should pass, got %q", res[1].Decision)
	}
}

func TestBatchRun_AuditChainPopulated(t *testing.T) {
	b, path := openBatch(t, nil)
	_, err := b.Run(context.Background(), strings.NewReader("112\n5551234567\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	raw, _ := os.ReadFile(path) //nolint:gosec // G304 — path is from t.TempDir()
	// 2 input lines → 2 audit entries.
	n := strings.Count(string(raw), "\n")
	if n != 2 {
		t.Fatalf("audit entries = %d, want 2; raw:\n%s", n, raw)
	}
	if !strings.Contains(string(raw), `"decision":"short"`) {
		t.Fatalf("short entry missing in payload: %s", raw)
	}
	if !strings.Contains(string(raw), `"decision":"allow"`) {
		t.Fatalf("allow entry missing in payload: %s", raw)
	}
}

func TestBatchRun_SkipsBlankAndComments(t *testing.T) {
	b, _ := openBatch(t, nil)
	input := strings.NewReader(`
# header
5551234567

# footer
`)
	res, _ := b.Run(context.Background(), input)
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1", len(res))
	}
}

func TestBatchRun_RequiresWriter(t *testing.T) {
	b := &dial.Batch{}
	_, err := b.Run(context.Background(), strings.NewReader("112\n"))
	if err == nil {
		t.Fatal("expected error when Writer is nil")
	}
}

func TestSummarise_CountsPerDecision(t *testing.T) {
	res := []dial.BatchResult{
		{Decision: "allow"},
		{Decision: "allow"},
		{Decision: "short"},
		{Decision: "blocked"},
		{Decision: "empty"},
		{Decision: "error"},
	}
	s := dial.Summarise(res)
	if s.Total != 6 || s.Allow != 2 || s.Short != 1 || s.Blocked != 1 || s.Empty != 1 || s.Errored != 1 {
		t.Fatalf("Summarise mismatch: %+v", s)
	}
}
