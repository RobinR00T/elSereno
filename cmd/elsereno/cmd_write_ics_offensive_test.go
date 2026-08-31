//go:build offensive

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteFINSProxyDryRun_PrintsMutation(t *testing.T) {
	cmd := newWriteFINSProxyDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "127.0.0.1:9600", "--fins-command", "0x01:0x02"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"finsudp", "proxy_session", "127.0.0.1:9600", "PayloadHash:", "confirm-token not minted"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteFINSProxyDryRun_RequiresTargetAndCommand(t *testing.T) {
	// Missing --target.
	c1 := newWriteFINSProxyDryRunCmd()
	c1.SetOut(&bytes.Buffer{})
	c1.SetErr(&bytes.Buffer{})
	c1.SetArgs([]string{"--fins-command", "0x01:0x02"})
	if err := c1.Execute(); err == nil {
		t.Error("Execute without --target should fail")
	}
	// Missing --fins-command.
	c2 := newWriteFINSProxyDryRunCmd()
	c2.SetOut(&bytes.Buffer{})
	c2.SetErr(&bytes.Buffer{})
	c2.SetArgs([]string{"--target", "x:9600"})
	if err := c2.Execute(); err == nil {
		t.Error("Execute without --fins-command should fail")
	}
	// Malformed --fins-command.
	c3 := newWriteFINSProxyDryRunCmd()
	c3.SetOut(&bytes.Buffer{})
	c3.SetErr(&bytes.Buffer{})
	c3.SetArgs([]string{"--target", "x:9600", "--fins-command", "nope"})
	if err := c3.Execute(); err == nil {
		t.Error("Execute with a malformed --fins-command should fail")
	}
}

func TestWriteSLMPProxyDryRun_PrintsMutation(t *testing.T) {
	cmd := newWriteSLMPProxyDryRunCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--target", "127.0.0.1:5007", "--slmp-command", "0x1401"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"slmp", "proxy_session", "127.0.0.1:5007", "PayloadHash:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestICSProxyDryRun_TokenStableWithTarget guards that the printed
// PayloadHash is deterministic and target-bound (the dry-run and the
// proxy handler must agree on the same SessionMutation, or the minted
// token would never match at Authorise time).
func TestICSProxyDryRun_TokenStableWithTarget(t *testing.T) {
	run := func(args ...string) string {
		cmd := newWriteSLMPProxyDryRunCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		return buf.String()
	}
	a := run("--target", "host-a:5007", "--slmp-command", "0x1401")
	b := run("--target", "host-a:5007", "--slmp-command", "0x1401")
	c := run("--target", "host-b:5007", "--slmp-command", "0x1401")
	if hashLine(a) != hashLine(b) {
		t.Error("PayloadHash not deterministic for identical inputs")
	}
	if hashLine(a) == hashLine(c) {
		t.Error("PayloadHash did not change with the target")
	}
}

func hashLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "PayloadHash:") {
			return line
		}
	}
	return ""
}
