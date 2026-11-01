//go:build offensive

package main

import "testing"

func TestCredsCheckHTTPRequiresTargetAndAuth(t *testing.T) {
	t.Parallel()
	// Missing --target.
	cmd := newCredsCheckHTTPCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
	// --target present but no --confirm-authorized: must refuse.
	cmd = newCredsCheckHTTPCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs([]string{"--target", "https://x.invalid"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected refusal without --confirm-authorized")
	}
}

func TestCredsCheckReuseValidation(t *testing.T) {
	t.Parallel()
	run := func(args ...string) error {
		cmd := newCredsCheckReuseCmd()
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		cmd.SetArgs(args)
		return cmd.Execute()
	}
	if run() == nil {
		t.Error("missing --target must error")
	}
	if run("--target", "https://x.invalid") == nil {
		t.Error("missing --confirm-authorized must error")
	}
	if run("--target", "x:22", "--confirm-authorized", "--protocol", "telnet") == nil {
		t.Error("bad --protocol must error")
	}
	// Valid flags but no credential source: fails before any vault unlock.
	if run("--target", "x:22", "--confirm-authorized", "--protocol", "ssh") == nil {
		t.Error("missing credential source must error")
	}
}
