//go:build offensive

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	modwrite "local/elsereno/offensive/write/modbus"
)

// modbusAllowlistHashHex is the hex-encoded AllowlistHash for
// the given target + allowlist. Kept here as a test helper so
// TestWriteModbusProxyDryRun_RoundTripHashStable can compare
// against the dry-run's printed hash.
func modbusAllowlistHashHex(target string, allowed []modwrite.AllowedWrite) string {
	h := modwrite.AllowlistHash(target, allowed)
	return hex.EncodeToString(h[:])
}

func TestWriteModbusProxyDryRun_OutputShape(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc.example.com:502",
		"--function", "6",
		"--function", "16",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Protocol:     modbus",
		"Operation:    proxy_session",
		"Target:       plc.example.com:502",
		"Functions:    6, 16",
		"Unit:         any (0)",
		"AddressRange: any",
		"PayloadHash:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestWriteModbusProxyDryRun_TightGateRenders(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc:502",
		"--function", "6",
		"--unit", "3",
		"--address-from", "100",
		"--address-to", "200",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Unit:         3") {
		t.Errorf("expected Unit: 3 in output:\n%s", out)
	}
	if !strings.Contains(out, "AddressRange: 100..200") {
		t.Errorf("expected AddressRange: 100..200:\n%s", out)
	}
}

func TestWriteModbusProxyDryRun_RequiresTarget(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--function", "6"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --target-required error")
	}
}

func TestWriteModbusProxyDryRun_RequiresFunction(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "plc:502"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected --function-required error")
	}
}

func TestWriteModbusProxyDryRun_FunctionOutOfRange(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "plc:502", "--function", "256"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected function-out-of-range error")
	}
}

// TestWriteModbusProxyDryRun_StructuredWriteFlag — v1.12 chunk 4
// adds --write unit=N;fc=M;start=A;end=B (repeatable) so the
// operator can allowlist multiple (unit, FC, address-range)
// tuples in one session without the legacy --function+--unit+
// --address-* single-shape limitation.
func TestWriteModbusProxyDryRun_StructuredWriteFlag(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc:502",
		"--write", "unit=1;fc=6;start=100;end=200",
		"--write", "unit=2;fc=16;start=400;end=500",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Writes:       2 structured entries",
		"unit=1;fc=6;start=100;end=200",
		"unit=2;fc=16;start=400;end=500",
		"PayloadHash:  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// TestWriteModbusProxyDryRun_StructuredWriteRoundTrip — --write
// entries round-trip through --emit-allow-file into the YAML's
// structured `writes:` block.
func TestWriteModbusProxyDryRun_StructuredWriteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/allow.yaml"
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc:502",
		"--write", "unit=1;fc=6;start=100;end=200",
		"--write", "fc=5", // any unit, any address
		"--emit-allow-file", path,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rawBytes, err := os.ReadFile(path) //nolint:gosec // G304 — test-owned t.TempDir() path
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	raw := string(rawBytes)
	for _, want := range []string{"writes:", "fc: 5", "unit: 1", "fc: 6", "start: 100", "end: 200"} {
		if !strings.Contains(raw, want) {
			t.Errorf("expected %q in YAML:\n%s", want, raw)
		}
	}

	// Load the emitted YAML back and confirm the allowlist matches.
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(opts.modbusWritesYAML) != 2 {
		t.Fatalf("expected 2 structured writes, got %d", len(opts.modbusWritesYAML))
	}
	// Sort order: (unit, fc, start, end). Entry (unit=0, fc=5)
	// comes before (unit=1, fc=6).
	if opts.modbusWritesYAML[0].FC != 5 || opts.modbusWritesYAML[0].Unit != 0 {
		t.Errorf("[0] = %+v, want unit=0 fc=5", opts.modbusWritesYAML[0])
	}
	if opts.modbusWritesYAML[1].Unit != 1 || opts.modbusWritesYAML[1].FC != 6 ||
		opts.modbusWritesYAML[1].Start != 100 || opts.modbusWritesYAML[1].End != 200 {
		t.Errorf("[1] = %+v, want unit=1 fc=6 start=100 end=200", opts.modbusWritesYAML[1])
	}
}

// TestParseModbusWriteFlag_Valid — canonical inputs parse.
func TestParseModbusWriteFlag_Valid(t *testing.T) {
	cases := []struct {
		in                 string
		wantUnit           uint8
		wantFC             uint8
		wantStart, wantEnd uint16
	}{
		{"fc=6", 0, 6, 0, 0},
		{"unit=1;fc=6", 1, 6, 0, 0},
		{"unit=1;fc=6;start=100;end=200", 1, 6, 100, 200},
		{" UNIT = 2 ; FC = 16 ; START = 400 ; END = 500 ", 2, 16, 400, 500},
	}
	for _, c := range cases {
		got, err := parseModbusWriteFlag(c.in)
		if err != nil {
			t.Errorf("parse(%q): %v", c.in, err)
			continue
		}
		if got.Unit != c.wantUnit || uint8(got.FC) != c.wantFC ||
			got.StartAddr != c.wantStart || got.EndAddr != c.wantEnd {
			t.Errorf("parse(%q) = %+v, want unit=%d fc=%d start=%d end=%d",
				c.in, got, c.wantUnit, c.wantFC, c.wantStart, c.wantEnd)
		}
	}
}

// TestParseModbusWriteFlag_Invalid — rejection cases.
func TestParseModbusWriteFlag_Invalid(t *testing.T) {
	for _, in := range []string{
		"",                       // empty
		"unit=1",                 // missing fc
		"unit=256;fc=6",          // unit too big
		"fc=0",                   // fc zero
		"fc=256",                 // fc too big
		"unit=abc;fc=6",          // non-numeric unit
		"fc=6;start=200;end=100", // start > end
		"fc=6;unknown=3",         // unknown key
	} {
		if _, err := parseModbusWriteFlag(in); err == nil {
			t.Errorf("parse(%q): expected error", in)
		}
	}
}

// TestWriteModbusProxyDryRun_RoundTripHashStable — the hash of
// the session mutation must be identical whether the operator
// supplies the allowlist via CLI --write flags OR via a reloaded
// YAML allow-file. Otherwise the minted confirm-token doesn't
// match on `proxy listen --allow-file` and the session refuses.
func TestWriteModbusProxyDryRun_RoundTripHashStable(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/allow.yaml"

	// Step 1: dry-run writes YAML.
	dry := newWriteModbusProxyDryRunCmd()
	dry.SilenceUsage = true
	var dryOut bytes.Buffer
	dry.SetOut(&dryOut)
	dry.SetErr(&dryOut)
	dry.SetArgs([]string{
		"--target", "plc:502",
		"--write", "unit=1;fc=6;start=100;end=200",
		"--write", "unit=2;fc=16;start=400;end=500",
		"--emit-allow-file", path,
	})
	if err := dry.Execute(); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	dryHash := extractPayloadHash(t, dryOut.String())

	// Step 2: reload the emitted YAML and confirm the rebuilt
	// allowlist hash matches.
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		t.Fatalf("reload: %v", err)
	}
	allowed, err := buildModbusAllowlist(opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	loadedHash := modbusAllowlistHashHex(opts.target, allowed)
	if dryHash != loadedHash {
		t.Fatalf("hash drift across round-trip:\n  dry-run:  %s\n  reloaded: %s", dryHash, loadedHash)
	}
}

// extractPayloadHash pulls the "PayloadHash:  <hex>" line from a
// dry-run output.
func extractPayloadHash(t *testing.T, out string) string {
	t.Helper()
	const prefix = "PayloadHash:  "
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	t.Fatalf("no PayloadHash line in dry-run output:\n%s", out)
	return ""
}

// TestWriteModbusProxyDryRun_TightGateRoundTrips — v1.12 chunk 4
// closed the v1.9 carry-over. --unit / --address-from /
// --address-to combined with --emit-allow-file now emit a
// structured `writes:` entry that preserves the gate tightening
// across round-trip. (Previously this combination was refused at
// dry-run time because the YAML schema only persisted
// `functions:`.)
func TestWriteModbusProxyDryRun_TightGateRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/allow.yaml"
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc:502",
		"--function", "6",
		"--unit", "1",
		"--address-from", "100",
		"--address-to", "200",
		"--emit-allow-file", path,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--unit + --emit-allow-file should succeed (v1.12+): %v", err)
	}
	rawBytes, err := os.ReadFile(path) //nolint:gosec // G304 — test-owned t.TempDir() path
	if err != nil {
		t.Fatalf("read emitted YAML: %v", err)
	}
	raw := string(rawBytes)
	// The `functions:` legacy key should NOT appear (unit/addr
	// mean we need structured entries). `writes:` SHOULD appear
	// with the expected unit/fc/start/end.
	if strings.Contains(raw, "functions:") {
		t.Errorf("tight gate should emit writes: only, not functions:\n%s", raw)
	}
	for _, want := range []string{"writes:", "unit: 1", "fc: 6", "start: 100", "end: 200"} {
		if !strings.Contains(raw, want) {
			t.Errorf("expected %q in emitted YAML:\n%s", want, raw)
		}
	}
}
