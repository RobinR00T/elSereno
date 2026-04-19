//go:build offensive

package main

import "github.com/spf13/cobra"

// registerOffensiveCmds attaches the offensive-build verbs to the
// root command. Called from newRootCmd() via offensiveCmds().
func registerOffensiveCmds(root *cobra.Command) {
	root.AddCommand(newWriteCmd())
	root.AddCommand(newExploitCmd())
	root.AddCommand(newHarvestCmd())
	root.AddCommand(newDialCmd())
}
