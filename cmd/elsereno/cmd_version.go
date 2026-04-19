package main

import (
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print binary version, commit, and build date",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf("elsereno %s\ncommit %s\nbuilt %s\n", version, commit, date)
			return nil
		},
	}
}
