package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/scope"
)

// newLintCmd validates elsereno.yaml and (optionally) scope.yaml.
// Exit 78 (EX_CONFIG) on validation failures.
func newLintCmd() *cobra.Command {
	var scopePath string
	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Validate elsereno.yaml and optional scope.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, path, err := loadConfig()
			if err != nil {
				if errors.Is(err, config.ErrUnknownConfigField) || errors.Is(err, config.ErrInvalidConfig) {
					return fail(core.ExitConfig, err)
				}
				return fail(core.ExitSoftware, err)
			}
			if path == "" {
				cmd.Println("config: ok (defaults only; no file discovered)")
			} else {
				cmd.Printf("config: ok (%s)\n", path)
			}
			if scopePath != "" {
				if _, err := scope.Load(scopePath); err != nil {
					return fail(core.ExitConfig, err)
				}
				cmd.Printf("scope:  ok (%s)\n", scopePath)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&scopePath, "scope", "", "also validate this scope.yaml")
	return cmd
}

// newFmtCmd round-trips elsereno.yaml / scope.yaml through the YAML
// encoder so formatting is canonical. Prints to stdout unless
// `--write` is set.
func newFmtCmd() *cobra.Command {
	var write bool
	cmd := &cobra.Command{
		Use:   "fmt <path>",
		Short: "Re-emit a YAML config with canonical formatting",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			// #nosec G304 -- caller-supplied path
			raw, err := os.ReadFile(path)
			if err != nil {
				return fail(core.ExitIOErr, err)
			}
			var doc any
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				return fail(core.ExitDataErr, err)
			}
			b, err := yaml.Marshal(doc)
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			if !write {
				cmd.Print(string(b))
				return nil
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				return fail(core.ExitIOErr, err)
			}
			_, _ = fmt.Fprintln(os.Stderr, "formatted", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&write, "write", false, "write back to <path> instead of printing")
	return cmd
}
