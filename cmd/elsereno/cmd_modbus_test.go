package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Three Modbus/TCP frames (MBAP + PDU), hex. MBAP = TxID(2) Proto(2)
// Length(2) Unit(1); Length covers Unit + PDU.
const (
	// FC 3 Read Holding Registers (silent).
	mbReadHex = "000100000006 01 03 0000 000A"
	// FC 6 Write Single Register: addr 0x0010, value 0x00FF.
	mbWriteHex = "000200000006 01 06 0010 00FF"
	// FC 8 sub 0x0001 Restart Communications (mutating diagnostic).
	mbDiagHex = "000300000006 01 08 0001 FF00"
)

func TestModbusMonitorFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "frames.txt")
	body := "# read\n" + mbReadHex + "\n# write\n" + mbWriteHex + "\n# diag\n" + mbDiagHex + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newModbusMonitorCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--file", path})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "write_observed") {
		t.Fatalf("expected write_observed, got:\n%s", out)
	}
	if !strings.Contains(out, "dangerous_diagnostic") {
		t.Fatalf("expected dangerous_diagnostic, got:\n%s", out)
	}
	if !strings.Contains(out, "processed 3 Modbus frames, 2 events") {
		t.Fatalf("expected 3 frames / 2 events summary, got:\n%s", out)
	}
}

func TestModbusMonitorRequiresFile(t *testing.T) {
	t.Parallel()
	cmd := newModbusMonitorCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when --file is missing")
	}
}
