//go:build offensive

package main

import (
	"bytes"
	"strings"
	"testing"
)

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

// TestWriteModbusProxyDryRun_EmitGuardsTightGate — the YAML
// schema only persists `functions:`, so if the operator asks for
// unit / address-range tightening AND emit-allow-file, the gate
// would widen silently on the round-trip. The command refuses
// that combination with a clear error pointing at the workaround.
func TestWriteModbusProxyDryRun_EmitGuardsTightGate(t *testing.T) {
	cmd := newWriteModbusProxyDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "plc:502",
		"--function", "6",
		"--unit", "1",
		"--emit-allow-file", "/tmp/should-not-write.yaml",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error when --unit + --emit-allow-file combined")
	}
	if !strings.Contains(err.Error(), "not compatible") {
		t.Errorf("error should mention incompatibility, got: %v", err)
	}
}
