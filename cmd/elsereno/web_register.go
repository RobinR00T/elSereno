//go:build !mini

package main

import "github.com/spf13/cobra"

// registerWebVerbs wires the HTTP-server-dependent CLI verbs
// (`serve`, `api openapi`) into the root command. Excluded from
// the mini build via the !mini build tag — the mini variant
// targets device deployments that don't host the dashboard or
// expose the API.
//
// The mini build's twin (web_register_mini.go) registers stub
// verbs with the same names that print a descriptive error so
// operators see "this verb requires the default / offensive
// build" rather than "unknown command".
func registerWebVerbs(root *cobra.Command) {
	root.AddCommand(newServeCmd())
	root.AddCommand(newAPICmd())
}
