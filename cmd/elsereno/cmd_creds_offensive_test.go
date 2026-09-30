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
