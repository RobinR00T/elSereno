//go:build !mini

package main

import (
	"os"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/web/openapi"
)

// newAPICmd exposes meta-operations on the live ElSereno HTTP API,
// starting with emitting the code-sourced OpenAPI 3.1 YAML. The
// `docs/openapi.yaml` snapshot is regenerated via
// `elsereno api openapi > docs/openapi.yaml`.
func newAPICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "api",
		Short: "HTTP API meta-operations",
	}
	cmd.AddCommand(newAPIOpenAPICmd())
	return cmd
}

func newAPIOpenAPICmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "openapi",
		Short: "Emit the OpenAPI 3.1 YAML for ElSereno's HTTP API",
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc := openapi.Spec(version)
			body, err := openapi.Marshal(doc)
			if err != nil {
				return fail(core.ExitError, err)
			}
			if out == "" {
				_, _ = cmd.OutOrStdout().Write(body)
				return nil
			}
			// #nosec G306 -- 0644 is the convention for generated
			// OpenAPI artefacts checked into the repo.
			if err := os.WriteFile(out, body, 0o644); err != nil {
				return fail(core.ExitIOErr, err)
			}
			cmd.Printf("wrote %s (%d bytes)\n", out, len(body))
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "optional output file (default: stdout)")
	return cmd
}
