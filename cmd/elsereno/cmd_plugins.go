package main

import (
	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage protocol plugins",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List plugins registered in this build",
		RunE: func(cmd *cobra.Command, _ []string) error {
			plugins := core.RegisteredPlugins()
			if len(plugins) == 0 {
				cmd.Println("no plugins registered in this build")
				cmd.Println("(default build is read-only; rebuild with -tags offensive to add offensive plugins)")
				return nil
			}
			for _, p := range plugins {
				cmd.Printf("%-10s  %s\n", p.Name, p.Description)
			}
			return nil
		},
	})
	return cmd
}
