package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate configuration",
	}
	cmd.AddCommand(newConfigShowCmd())
	cmd.AddCommand(newConfigLintCmd())
	return cmd
}

func newConfigShowCmd() *cobra.Command {
	var unsafe bool
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print the effective configuration",
		Long: "config show prints the merged configuration (defaults + file). " +
			"Secrets are redacted unless --unsafe is set.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, path, err := loadConfig()
			if err != nil {
				return fail(core.ExitConfig, err)
			}
			if path != "" {
				cmd.Printf("# source: %s\n", path)
			} else {
				cmd.Println("# source: defaults (no config file discovered)")
			}

			// The Config struct does not currently carry credential
			// fields; creds and vault passphrases live in the vault,
			// never in elsereno.yaml (ADR-026). The redaction pass is a
			// no-op today but is kept as a seam for future fields.
			_ = unsafe

			format := flagFormat
			if format == "" {
				format = "yaml"
			}
			switch format {
			case "yaml":
				return emitYAML(cmd.OutOrStdout(), cfg)
			case "json":
				return emitJSON(cmd.OutOrStdout(), cfg)
			case "table":
				return emitTable(cmd.OutOrStdout(), cfg)
			default:
				return fail(core.ExitUsage, fmt.Errorf("unknown --format %q (use yaml|json|table)", format))
			}
		},
	}
	cmd.Flags().BoolVar(&unsafe, "unsafe", false, "reveal redacted fields (none today; reserved)")
	return cmd
}

func newConfigLintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lint",
		Short: "Validate the configuration file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, path, err := loadConfig()
			if err != nil {
				if errors.Is(err, config.ErrUnknownConfigField) || errors.Is(err, config.ErrInvalidConfig) {
					return fail(core.ExitConfig, err)
				}
				return fail(core.ExitSoftware, err)
			}
			if path == "" {
				cmd.Println("ok (defaults only; no file discovered)")
				return nil
			}
			cmd.Printf("ok: %s\n", path)
			return nil
		},
	}
}

// loadConfig wires the standard discovery order into the Loader.
func loadConfig() (config.Config, string, error) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	l := config.NewLoader(config.LookupOrder{
		Explicit: flagConfig,
		Env:      os.Getenv("ELSERENO_CONFIG"),
		HomeDir:  home,
		XDG:      os.Getenv("XDG_CONFIG_HOME"),
		CWD:      cwd,
	})
	return l.Load(context.TODO())
}

func emitYAML(w any, cfg config.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return fail(core.ExitSoftware, err)
	}
	return writeAll(w, b)
}

func emitJSON(w any, cfg config.Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fail(core.ExitSoftware, err)
	}
	return writeAll(w, append(b, '\n'))
}

func emitTable(w any, cfg config.Config) error {
	tw := tabwriter.NewWriter(anyAsWriter(w), 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "KEY\tVALUE"); err != nil {
		return fail(core.ExitIOErr, err)
	}
	paths, err := flattenForTable(cfg)
	if err != nil {
		return fail(core.ExitSoftware, err)
	}
	for _, p := range paths {
		if _, err := fmt.Fprintf(tw, "%s\t%v\n", p.key, p.value); err != nil {
			return fail(core.ExitIOErr, err)
		}
	}
	return tw.Flush()
}

type tableRow struct {
	key   string
	value any
}

func flattenForTable(cfg config.Config) ([]tableRow, error) {
	// Marshal to YAML then back into an ordered []byte is overkill; use
	// json round-trip for a stable canonical shape.
	b, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := json.Unmarshal(b, &tree); err != nil {
		return nil, err
	}
	rows := make([]tableRow, 0, 64)
	flattenJSON("", tree, &rows)
	return rows, nil
}

func flattenJSON(prefix string, node any, out *[]tableRow) {
	switch v := node.(type) {
	case map[string]any:
		for k, child := range v {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			flattenJSON(path, child, out)
		}
	default:
		*out = append(*out, tableRow{key: prefix, value: v})
	}
}

// writeAll and anyAsWriter lift cobra's OutOrStdout (io.Writer) through
// without importing io at the package level here.
func writeAll(w any, b []byte) error {
	if ww, ok := w.(interface{ Write([]byte) (int, error) }); ok {
		_, err := ww.Write(b)
		return err
	}
	return errors.New("config: output is not writable")
}

func anyAsWriter(w any) interface {
	Write([]byte) (int, error)
} {
	if ww, ok := w.(interface{ Write([]byte) (int, error) }); ok {
		return ww
	}
	return nopWriter{}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
