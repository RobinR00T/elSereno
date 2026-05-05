package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/scanorch"
)

// writeTargetFile creates a list:-format input file in t.TempDir.
func writeTargetFile(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	return path
}

// TestDefaultScanRunner_NoPlugin returns the sentinel.
func TestDefaultScanRunner_NoPlugin(t *testing.T) {
	r := &defaultScanRunner{}
	_, err := r.Run(context.Background(), scanorch.Job{Input: "stdin"})
	if !errors.Is(err, ErrRunnerNoPlugin) {
		t.Errorf("err = %v, want ErrRunnerNoPlugin", err)
	}
}

// TestDefaultScanRunner_TooManyPlugins refuses multi-plugin
// jobs (deferred to a future cycle).
func TestDefaultScanRunner_TooManyPlugins(t *testing.T) {
	r := &defaultScanRunner{}
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:   "stdin",
		Plugins: []string{"modbus", "s7"},
	})
	if !errors.Is(err, ErrRunnerTooManyPlugins) {
		t.Errorf("err = %v, want ErrRunnerTooManyPlugins", err)
	}
}

// TestDefaultScanRunner_UnknownPlugin returns the sentinel.
func TestDefaultScanRunner_UnknownPlugin(t *testing.T) {
	r := &defaultScanRunner{}
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:   "stdin",
		Plugins: []string{"this-plugin-does-not-exist"},
	})
	if !errors.Is(err, ErrRunnerUnknownPlugin) {
		t.Errorf("err = %v, want ErrRunnerUnknownPlugin", err)
	}
}

// TestDefaultScanRunner_BadInput propagates the parse error.
func TestDefaultScanRunner_BadInput(t *testing.T) {
	r := &defaultScanRunner{}
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:   "not-a-known-kind",
		Plugins: []string{"modbus"},
	})
	if err == nil {
		t.Fatal("expected error for malformed input")
	}
	if !strings.Contains(err.Error(), "parse input") {
		t.Errorf("err = %v, want a parse-input wrapper", err)
	}
}

// TestDefaultScanRunner_EmptyTargets: an empty list file is
// rejected by the input parser with a "no targets parsed"
// error. The runner propagates it through the parse-input
// wrapper. (Actually-empty target slices are unreachable on
// the happy path; the parser refuses them upstream.)
func TestDefaultScanRunner_EmptyTargets(t *testing.T) {
	r := &defaultScanRunner{}
	emptyFile := writeTargetFile(t, "")
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:       "list:" + emptyFile,
		Plugins:     []string{"banner"},
		DefaultPort: 80,
	})
	if err == nil {
		t.Fatal("expected error for empty input file")
	}
	if !strings.Contains(err.Error(), "no targets parsed") {
		t.Errorf("err = %v, want a 'no targets parsed' propagation", err)
	}
}

// TestDefaultScanRunner_StatsPopulated runs against a non-
// listening loopback host so the scanner produces only errors
// (no findings). The runner should still return TargetsSeen +
// TargetsScanned correctly accounted.
//
// We use 127.0.0.1:1 because port 1 is reliably closed; the
// banner plugin's TCP dial fails fast → counted as scanned-
// with-no-finding.
func TestDefaultScanRunner_StatsPopulated(t *testing.T) {
	r := &defaultScanRunner{}
	listFile := writeTargetFile(t, "127.0.0.1:1\n127.0.0.2:1\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stats, err := r.Run(ctx, scanorch.Job{
		Input:       "list:" + listFile,
		Plugins:     []string{"banner"},
		DefaultPort: 80,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if stats.TargetsSeen != 2 {
		t.Errorf("TargetsSeen = %d, want 2", stats.TargetsSeen)
	}
	// TargetsScanned should equal TargetsSeen for a complete
	// drain (each target either produced a finding or an error).
	if stats.TargetsScanned != 2 {
		t.Errorf("TargetsScanned = %d, want 2 (banner emits a finding per dial-attempt)", stats.TargetsScanned)
	}
}

// TestLookupPluginByName: a known plugin (banner) is found.
func TestLookupPluginByName_Banner(t *testing.T) {
	p, ok := lookupPluginByName("banner")
	if !ok {
		t.Fatal("banner plugin not found in registry")
	}
	if p.Name != "banner" {
		t.Errorf("Name = %q", p.Name)
	}
}

// TestLookupPluginByName_Missing returns ok=false.
func TestLookupPluginByName_Missing(t *testing.T) {
	_, ok := lookupPluginByName("not-a-real-plugin")
	if ok {
		t.Errorf("ok = true for unknown plugin")
	}
}
