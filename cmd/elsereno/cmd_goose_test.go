package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two GOOSE frames for the same publisher (goID "t"): baseline stNum 1,
// then an injected stNum 9 (the high-stNum override). Same bytes the
// demo script uses.
const (
	gooseBaselineHex  = "010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850101 860100 880101"
	gooseInjectionHex = "010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850109 860100 880101"
)

func TestGooseMonitorFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "frames.txt")
	body := "# baseline\n" + gooseBaselineHex + "\n# injection\n" + gooseInjectionHex + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newGooseMonitorCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--file", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "stnum_jump") {
		t.Fatalf("expected stnum_jump on the injected frame, got:\n%s", out)
	}
	if !strings.Contains(out, "processed 2 GOOSE/SV frames") {
		t.Fatalf("expected summary of 2 frames, got:\n%s", out)
	}
}

func TestGooseMonitorFlagValidation(t *testing.T) {
	t.Parallel()
	// Neither --file nor --iface.
	cmd := newGooseMonitorCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when neither --file nor --iface is set")
	}

	// Both.
	cmd2 := newGooseMonitorCmd()
	cmd2.SilenceUsage, cmd2.SilenceErrors = true, true
	cmd2.SetArgs([]string{"--file", "x", "--iface", "eth0"})
	if err := cmd2.Execute(); err == nil {
		t.Fatal("expected error when both --file and --iface are set")
	}
}

func TestGooseMonitorIfaceErrors(t *testing.T) {
	t.Parallel()
	// A bogus interface must fail cleanly: off Linux with the
	// unsupported error, on Linux with an interface/permission error.
	// Either way, non-nil and no panic.
	cmd := newGooseMonitorCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--iface", "nonexistent-elsereno-test-iface-999"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for a bogus interface")
	}
}
