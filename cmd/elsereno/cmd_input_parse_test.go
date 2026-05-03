package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseInput_Stdin exercises the stdin path through an
// injected reader. The full list parser already has its own
// tests; this just proves the dispatcher wires them together.
func TestParseInput_Stdin(t *testing.T) {
	src := strings.NewReader("10.0.0.1:502\n10.0.0.2:102\n")
	targets, err := parseInput(context.Background(), inputParseOpts{
		InputKind: "stdin",
		Stdin:     src,
	})
	if err != nil {
		t.Fatalf("parseInput: %v", err)
	}
	if got := len(targets); got != 2 {
		t.Fatalf("targets = %d, want 2", got)
	}
}

// TestParseInput_ListFile writes a tiny target file + parses it.
func TestParseInput_ListFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	if err := writeFile(path, "192.0.2.1:80\n192.0.2.2:443\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	targets, err := parseInput(context.Background(), inputParseOpts{
		InputKind: "list:" + path,
	})
	if err != nil {
		t.Fatalf("parseInput: %v", err)
	}
	if got := len(targets); got != 2 {
		t.Errorf("targets = %d, want 2", got)
	}
}

// TestParseInput_ListMissingFile — surfaces the underlying
// os.Open error wrapped with the file path.
func TestParseInput_ListMissingFile(t *testing.T) {
	_, err := parseInput(context.Background(), inputParseOpts{
		InputKind: "list:" + filepath.Join(t.TempDir(), "nonexistent.txt"),
	})
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("err = %v, want 'no such file'", err)
	}
}

// TestParseInput_UnknownKind — operator typo bypasses every
// branch + reaches the default.
func TestParseInput_UnknownKind(t *testing.T) {
	_, err := parseInput(context.Background(), inputParseOpts{InputKind: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown input kind") {
		t.Errorf("err = %v, want 'unknown input kind'", err)
	}
}

// TestParseInput_NmapMissingFile — same shape as list, distinct
// branch in the dispatcher.
func TestParseInput_NmapMissingFile(t *testing.T) {
	_, err := parseInput(context.Background(), inputParseOpts{
		InputKind: "nmap:" + filepath.Join(t.TempDir(), "scan.xml"),
	})
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("err = %v, want 'no such file'", err)
	}
}

// TestParseInput_NmapMinimalXML drives the nmapxml parser
// through the dispatcher with the smallest-possible nmaprun
// document so we verify the wire-up without depending on
// fixtures elsewhere.
func TestParseInput_NmapMinimalXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.xml")
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host><address addr="10.0.0.1" addrtype="ipv4"/>
    <ports><port portid="502"><state state="open"/></port></ports>
  </host>
</nmaprun>
`
	if err := writeFile(path, xml); err != nil {
		t.Fatalf("write: %v", err)
	}
	targets, err := parseInput(context.Background(), inputParseOpts{
		InputKind: "nmap:" + path,
	})
	if err != nil {
		t.Fatalf("parseInput: %v", err)
	}
	if got := len(targets); got != 1 {
		t.Errorf("targets = %d, want 1 (got %v)", got, targets)
	}
}

// TestParseInput_StdinDefaultsToOsStdin — when Stdin is nil we
// fall back to os.Stdin. We can't easily test the actual fallback
// without redirecting the process's stdin; we just call with a
// cancelled context so the parser doesn't block on a real TTY.
func TestParseInput_StdinDefaultsToOsStdin(_ *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// May return ctx.Err() or empty list depending on how the
	// stdin parser interacts with a cancelled ctx. Either is
	// acceptable for proving the nil-Stdin guard.
	_, _ = parseInput(ctx, inputParseOpts{InputKind: "stdin"})
}

// writeFile is a small testing helper; cmd package has no
// shared test utility yet so we keep this local.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
