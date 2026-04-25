//go:build offensive

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestEmitCWMPRPCCaseWarnings_AllCanonical — when every
// operator-supplied RPC matches the canonical case, no warning
// is emitted.
func TestEmitCWMPRPCCaseWarnings_AllCanonical(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	emitCWMPRPCCaseWarnings(cmd, []string{
		"SetParameterValues", "Reboot", "Download", "FactoryReset",
	})
	if buf.Len() != 0 {
		t.Errorf("expected no warnings, got:\n%s", buf.String())
	}
}

// TestEmitCWMPRPCCaseWarnings_LowercaseFiresWarning — operator
// typed lowercase; warning fires with the canonical spelling.
func TestEmitCWMPRPCCaseWarnings_LowercaseFiresWarning(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	emitCWMPRPCCaseWarnings(cmd, []string{"setparametervalues", "REBOOT"})
	out := buf.String()
	if !strings.Contains(out, "SetParameterValues") {
		t.Errorf("expected canonical SetParameterValues hint, got:\n%s", out)
	}
	if !strings.Contains(out, "Reboot") {
		t.Errorf("expected canonical Reboot hint, got:\n%s", out)
	}
	if !strings.Contains(out, "case-sensitive") {
		t.Errorf("expected case-sensitive explanation, got:\n%s", out)
	}
}

// TestEmitCWMPRPCCaseWarnings_PrefixStripped — operator pasted
// `cwmp:setparametervalues`; warning still fires with canonical
// spelling.
func TestEmitCWMPRPCCaseWarnings_PrefixStripped(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	emitCWMPRPCCaseWarnings(cmd, []string{"cwmp:setparametervalues"})
	out := buf.String()
	if !strings.Contains(out, "SetParameterValues") {
		t.Errorf("expected canonical hint after prefix strip, got:\n%s", out)
	}
}

// TestEmitCWMPRPCCaseWarnings_VendorRPCSilent — RPC names not
// in the canonical TR-069 list (vendor extensions like
// `X_VENDOR_DoSomething`) don't trigger a warning.
func TestEmitCWMPRPCCaseWarnings_VendorRPCSilent(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	emitCWMPRPCCaseWarnings(cmd, []string{"X_VENDOR_DoSomething", "MyCustomRPC"})
	if buf.Len() != 0 {
		t.Errorf("vendor RPCs should not warn, got:\n%s", buf.String())
	}
}

// TestEmitCWMPRPCCaseWarnings_BlankAndPrefixOnlySkipped —
// trimmed-empty inputs (just whitespace, or `cwmp:`) skip the
// warning loop without panicking.
func TestEmitCWMPRPCCaseWarnings_BlankAndPrefixOnlySkipped(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	emitCWMPRPCCaseWarnings(cmd, []string{"   ", "cwmp:", ""})
	if buf.Len() != 0 {
		t.Errorf("blank/prefix-only inputs should not warn:\n%s", buf.String())
	}
}

// TestNewWriteCWMPDryRunCmd_CaseWarningOnLowercase — full CLI
// dry-run with a lowercase RPC fires the warning to stdout AND
// completes (the gate doesn't refuse — it just informs).
func TestNewWriteCWMPDryRunCmd_CaseWarningOnLowercase(t *testing.T) {
	cmd := newWriteCWMPDryRunCmd()
	cmd.SilenceUsage = true
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"--target", "acs:7547",
		"--rpc", "reboot", // lowercase typo
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "warning:") {
		t.Errorf("expected `warning:` line in dry-run output:\n%s", out)
	}
	if !strings.Contains(out, "Reboot") {
		t.Errorf("expected canonical Reboot in warning:\n%s", out)
	}
	// The dry-run still emits the standard fields.
	if !strings.Contains(out, "PayloadHash:") {
		t.Errorf("dry-run should still emit PayloadHash:\n%s", out)
	}
}
