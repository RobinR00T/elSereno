package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/core"
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

// TestDefaultScanRunner_UnknownPlugin returns the sentinel.
func TestDefaultScanRunner_UnknownPlugin(t *testing.T) {
	r := &defaultScanRunner{}
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:   "stdin",
		Plugins: []string{"this-plugin-does-not-exist"},
	}, nil)
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
	}, nil)
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
// wrapper.
func TestDefaultScanRunner_EmptyTargets(t *testing.T) {
	r := &defaultScanRunner{}
	emptyFile := writeTargetFile(t, "")
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:       "list:" + emptyFile,
		Plugins:     []string{"banner"},
		DefaultPort: 80,
	}, nil)
	if err == nil {
		t.Fatal("expected error for empty input file")
	}
	if !strings.Contains(err.Error(), "no targets parsed") {
		t.Errorf("err = %v, want a 'no targets parsed' propagation", err)
	}
}

// TestDefaultScanRunner_NoMatchingPlugins: a single plugin
// (modbus, port 502) against targets all on port 80 produces
// zero plugin × target matches → ErrRunnerNoMatchingPlugins.
func TestDefaultScanRunner_NoMatchingPlugins(t *testing.T) {
	r := &defaultScanRunner{}
	listFile := writeTargetFile(t, "127.0.0.1:80\n")
	_, err := r.Run(context.Background(), scanorch.Job{
		Input:       "list:" + listFile,
		Plugins:     []string{"modbus"}, // DefaultPort 502
		DefaultPort: 80,
	}, nil)
	if !errors.Is(err, ErrRunnerNoMatchingPlugins) {
		t.Errorf("err = %v, want ErrRunnerNoMatchingPlugins", err)
	}
}

// TestDefaultScanRunner_StatsPopulated: banner plugin
// (DefaultPort 0 → matches any target) probes both targets;
// closed loopback ports → only errors → TargetsScanned == N
// but FindingsCount == 0 (the banner plugin actually produces
// findings for refused-connection probes; verify reasonable
// shape rather than exact counts).
func TestDefaultScanRunner_StatsPopulated(t *testing.T) {
	r := &defaultScanRunner{}
	listFile := writeTargetFile(t, "127.0.0.1:1\n127.0.0.2:1\n")
	stats, err := r.Run(context.Background(), scanorch.Job{
		Input:       "list:" + listFile,
		Plugins:     []string{"banner"},
		DefaultPort: 80,
	}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if stats.TargetsSeen != 2 {
		t.Errorf("TargetsSeen = %d, want 2", stats.TargetsSeen)
	}
	if stats.TargetsScanned != 2 {
		t.Errorf("TargetsScanned = %d, want 2", stats.TargetsScanned)
	}
}

// TestDefaultScanRunner_MultiPlugin: two plugins, one matches
// the target's port and the other doesn't → only the matching
// plugin produces probe-attempts, but the runner doesn't error.
func TestDefaultScanRunner_MultiPlugin(t *testing.T) {
	r := &defaultScanRunner{}
	listFile := writeTargetFile(t, "127.0.0.1:1\n")
	// modbus (502) doesn't match :1; banner (port 0 → matches
	// any) does. Net effect: 1 probe attempt via banner.
	stats, err := r.Run(context.Background(), scanorch.Job{
		Input:       "list:" + listFile,
		Plugins:     []string{"modbus", "banner"},
		DefaultPort: 502,
	}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if stats.TargetsScanned != 1 {
		t.Errorf("TargetsScanned = %d, want 1 (banner matched, modbus didn't)", stats.TargetsScanned)
	}
}

// TestDefaultScanRunner_EmptyPluginsRunsAll: a Job with no
// plugin names runs every registered plugin. Most won't match
// the loopback port, but banner (DefaultPort 0) WILL, so the
// dispatch count > 0 and the runner returns success.
func TestDefaultScanRunner_EmptyPluginsRunsAll(t *testing.T) {
	r := &defaultScanRunner{}
	listFile := writeTargetFile(t, "127.0.0.1:1\n")
	stats, err := r.Run(context.Background(), scanorch.Job{
		Input:       "list:" + listFile,
		Plugins:     nil,
		DefaultPort: 80,
	}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	// Banner plugin matched (DefaultPort 0 → any), so at least
	// 1 probe attempt.
	if stats.TargetsScanned < 1 {
		t.Errorf("TargetsScanned = %d, want ≥ 1", stats.TargetsScanned)
	}
}

// TestResolvePlugins_AllOnEmpty.
func TestResolvePlugins_AllOnEmpty(t *testing.T) {
	out, err := resolvePlugins(nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(out) != len(core.RegisteredPlugins()) {
		t.Errorf("got %d plugins, want %d", len(out), len(core.RegisteredPlugins()))
	}
}

// TestResolvePlugins_NamedSubset.
func TestResolvePlugins_NamedSubset(t *testing.T) {
	out, err := resolvePlugins([]string{"banner", "modbus"})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(out) != 2 {
		t.Errorf("got %d plugins, want 2", len(out))
	}
}

// TestResolvePlugins_Unknown returns the sentinel.
func TestResolvePlugins_Unknown(t *testing.T) {
	_, err := resolvePlugins([]string{"banner", "no-such-plugin"})
	if !errors.Is(err, ErrRunnerUnknownPlugin) {
		t.Errorf("err = %v, want ErrRunnerUnknownPlugin", err)
	}
}

// TestFilterByPort_DefaultZeroMatchesAll.
func TestFilterByPort_DefaultZeroMatchesAll(t *testing.T) {
	plugin := core.Plugin{PluginMetadata: core.PluginMetadata{DefaultPort: 0}}
	targets := []core.Target{
		{Port: 22}, {Port: 502}, {Port: 80},
	}
	out := filterByPort(targets, plugin)
	if len(out) != len(targets) {
		t.Errorf("got %d, want %d (DefaultPort=0 should match every target)", len(out), len(targets))
	}
}

// TestFilterByPort_PortMatch keeps only targets matching the
// plugin's DefaultPort.
func TestFilterByPort_PortMatch(t *testing.T) {
	plugin := core.Plugin{PluginMetadata: core.PluginMetadata{DefaultPort: 502}}
	targets := []core.Target{
		{Port: 22}, {Port: 502}, {Port: 80}, {Port: 502},
	}
	out := filterByPort(targets, plugin)
	if len(out) != 2 {
		t.Errorf("got %d, want 2", len(out))
	}
	for _, t2 := range out {
		if t2.Port != 502 {
			t.Errorf("matched target port = %d, want 502", t2.Port)
		}
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
