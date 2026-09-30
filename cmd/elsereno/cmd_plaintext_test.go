package main

import "testing"

func TestPlaintextCheckRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newPlaintextCheckCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}
