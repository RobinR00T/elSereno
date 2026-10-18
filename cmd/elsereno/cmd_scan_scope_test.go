package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// TestRunScan_ScopeOnlyWithFlag: scan applies a scope only when --scope
// names it. Until 2026-10-16 the help text, MANUAL and SECURITY said a
// scope.yaml in the working directory (or ~/.elsereno/) was loaded on its
// own; it never was. A scope.yaml that leaves the target out sits in both
// places: without --scope the target is probed anyway, with --scope it is
// dropped before any connection and scan exits with ExitNoInput.
func TestRunScan_ScopeOnlyWithFlag(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("ELSERENO_CONFIG", "")

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	targets := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(targets, []byte(ln.Addr().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Port 9 only: the listener's port is outside this scope.
	scopeYAML := []byte("version: 1\nports:\n  allow: [9]\n")
	scopeFile := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(scopeFile, scopeYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".elsereno"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".elsereno", "scope.yaml"), scopeYAML, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	run := func(scopePath string) error {
		cmd := &cobra.Command{}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd.SetContext(ctx)
		return runScan(cmd, scanOpts{
			inputKind:    "list:" + targets,
			scopePath:    scopePath,
			outputFormat: "ndjson",
			outputPath:   filepath.Join(dir, "out.ndjson"),
			noProgress:   true,
			plugins:      []string{"banner"},
		})
	}

	if err := run(""); err != nil {
		t.Fatalf("without --scope: %v (was ./scope.yaml or ~/.elsereno/scope.yaml applied?)", err)
	}
	if accepted.Load() == 0 {
		t.Fatal("without --scope the target was not probed")
	}

	before := accepted.Load()
	err = run(scopeFile)
	var ce cliError
	if !errors.As(err, &ce) || ce.code != core.ExitNoInput {
		t.Fatalf("with --scope: err = %v, want ExitNoInput (target outside the scope)", err)
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Fatalf("with --scope: err = %v, want it to name the scope", err)
	}
	if got := accepted.Load() - before; got != 0 {
		t.Fatalf("with --scope the out-of-scope target got %d connections, want 0", got)
	}
}

// TestNoTargetsErr: an input that gave nothing (an InternetDB IP with no
// data) is not blamed on the scope; one the scope emptied is.
func TestNoTargetsErr(t *testing.T) {
	if got := noTargetsErr("internetdb:192.0.2.10", 0).Error(); got != "--input internetdb:192.0.2.10 gave no targets" {
		t.Fatalf("no scope drop: %q", got)
	}
	if got := noTargetsErr("list:t.txt", 3).Error(); !strings.Contains(got, "scope") {
		t.Fatalf("scope drop: %q, want it to name the scope", got)
	}
}
