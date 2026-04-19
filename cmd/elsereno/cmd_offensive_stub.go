//go:build !offensive

package main

import "github.com/spf13/cobra"

// registerOffensiveCmds is a no-op in the default build. The
// offensive-build variant lives in cmd_offensive_register.go.
func registerOffensiveCmds(_ *cobra.Command) {}
