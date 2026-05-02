//go:build offensive

package main

import "github.com/spf13/cobra"

// registerOffensiveCmds attaches the offensive-build verbs to the
// root command. Called from newRootCmd() via offensiveCmds().
//
// The proxy stub added by newStubCmds() is replaced here with a
// real `proxy listen` implementation wired to the v1.4 write-
// gated handlers. Default-build keeps the stub's "planned"
// message.
func registerOffensiveCmds(root *cobra.Command) {
	root.AddCommand(newWriteCmd())
	root.AddCommand(newExploitCmd())
	root.AddCommand(newHarvestCmd())
	root.AddCommand(newDialCmd())

	replaceProxyStubWithOffensiveCmd(root)
}

// replaceProxyStubWithOffensiveCmd walks root.Commands(), removes
// the auto-registered "proxy" stub, and installs a real one that
// exposes `proxy listen`. The default-build stub (in
// cmd_stubs.go) never reaches this code path because this file
// is gated by `//go:build offensive`.
func replaceProxyStubWithOffensiveCmd(root *cobra.Command) {
	for _, existing := range root.Commands() {
		if existing.Name() == "proxy" {
			root.RemoveCommand(existing)
			break
		}
	}
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Protocol-aware interception proxy (offensive — run a write-gated proxy)",
	}
	cmd.AddCommand(newProxyListenCmd())
	cmd.AddCommand(newProxyReplayCmd())
	root.AddCommand(cmd)
}
