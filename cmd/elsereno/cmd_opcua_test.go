package main

import (
	"testing"
)

func TestOPCUAProbeAnonRequiresTarget(t *testing.T) {
	t.Parallel()
	cmd := newOPCUAProbeAnonCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error when --target is missing")
	}
}
