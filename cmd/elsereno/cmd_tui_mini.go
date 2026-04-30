//go:build mini

package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// newTUICmd in the mini build returns a stub verb that prints
// the canonical "not available in this build" error. Mirror of
// the cmd_serve / cmd_api stubs in web_register_mini.go.
func newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal UI (NOT in mini build)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return fail(core.ExitUnavail, fmt.Errorf("%s",
				"tui is not available in this build (the mini variant "+
					"excludes the bubbletea/lipgloss UI dependencies "+
					"to keep the binary small for device deployments). "+
					"Use the default `elsereno` binary or "+
					"`elsereno-offensive` from the same release."))
		},
	}
}
