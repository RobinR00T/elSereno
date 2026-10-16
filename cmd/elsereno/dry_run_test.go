package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// TestDryRun_OnlyTheVerbsThatImplementIt: the commands that let
// --dry-run through are exactly the schedule verbs whose RunE reads
// flagDryRun. A new command that implements it must be added here and
// marked with honoursDryRun; one that does not is refused by the root.
func TestDryRun_OnlyTheVerbsThatImplementIt(t *testing.T) {
	want := []string{
		"elsereno schedule clone",
		"elsereno schedule delete",
		"elsereno schedule disable",
		"elsereno schedule enable",
		"elsereno schedule import",
		"elsereno schedule pause-all",
		"elsereno schedule resume-all",
	}
	var got []string
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Annotations[dryRunAnnotation] == "honoured" {
			got = append(got, c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	root := newRootCmd()
	walk(root)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands that honour --dry-run:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// The flag's help text names them too; it is written by hand.
	usage := root.PersistentFlags().Lookup("dry-run").Usage
	for _, path := range want {
		if verb := path[strings.LastIndex(path, " ")+1:]; !strings.Contains(usage, verb) {
			t.Errorf("--dry-run help does not name %q: %s", verb, usage)
		}
	}
}

// TestDryRun_GuardCoversEveryCommand: cobra runs only the nearest
// persistent pre-run hook, so a subcommand that defined its own would
// switch the root's guard off for its whole subtree. None may, and the
// guard refuses the flag for every runnable command that is not marked.
// The guard is called directly, so no command runs even if it failed.
func TestDryRun_GuardCoversEveryCommand(t *testing.T) {
	root := newRootCmd()
	if root.PersistentPreRunE == nil {
		t.Fatal("the root has no --dry-run guard")
	}
	flagDryRun = true
	t.Cleanup(func() { flagDryRun = false })
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c != root && (c.PersistentPreRun != nil || c.PersistentPreRunE != nil) {
			t.Errorf("%s defines its own persistent pre-run hook, which hides the --dry-run guard", c.CommandPath())
		}
		if c.DisableFlagParsing {
			t.Errorf("%s disables flag parsing, so --dry-run would reach it as an argument", c.CommandPath())
		}
		if c.Runnable() && c.Annotations[dryRunAnnotation] != "honoured" {
			var ce cliError
			if err := root.PersistentPreRunE(c, nil); !errors.As(err, &ce) || ce.code != core.ExitUsage {
				t.Errorf("%s --dry-run: guard returned %v, want ExitUsage", c.CommandPath(), err)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
}

// TestDryRun_ScanRefusesIt: until 2026-10-16 `scan --dry-run` ignored
// the flag and scanned (PITF-089). Now it exits with ExitUsage before
// reading its input, and the target gets no connection.
func TestDryRun_ScanRefusesIt(t *testing.T) {
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
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
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

	root := newRootCmd()
	root.SetArgs([]string{"scan", "--dry-run", "--input", "list:" + targets,
		"--plugin", "banner", "--no-progress", "--output", filepath.Join(dir, "out.ndjson")})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = root.ExecuteContext(ctx)
	// Count only once the listener has stopped accepting.
	_ = ln.Close()
	<-acceptDone

	var ce cliError
	if !errors.As(err, &ce) || ce.code != core.ExitUsage {
		t.Fatalf("scan --dry-run: err = %v, want ExitUsage", err)
	}
	if !strings.Contains(err.Error(), "nothing was run") {
		t.Fatalf("message does not say nothing ran: %v", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("scan --dry-run opened %d connections, want 0", n)
	}
}

// TestDryRun_ScheduleDeleteStillHonoursIt: a verb that implements the
// flag keeps working with it.
func TestDryRun_ScheduleDeleteStillHonoursIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Cleanup(func() { flagDryRun = false })
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"schedule", "delete", "abc123", "--dry-run"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("schedule delete --dry-run: %v", err)
	}
	if !strings.Contains(out.String(), "[dry-run] would DELETE abc123") {
		t.Fatalf("output = %q", out.String())
	}
}
