package main

import "testing"

func TestS7ProbeProtectionRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newS7ProbeProtectionCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}

func TestS7ProbeIdentityRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newS7ProbeIdentityCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}
