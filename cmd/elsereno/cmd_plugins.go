package main

import (
	"encoding/json"
	"sort"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage protocol plugins",
	}
	cmd.AddCommand(newPluginsListCmd())
	cmd.AddCommand(newPluginsPortsCmd())
	return cmd
}

// newPluginsListCmd returns the existing `plugins list`
// sub-verb. Pulled out from newPluginsCmd's inline literal
// so the parent stays focused.
func newPluginsListCmd() *cobra.Command {
	return &cobra.Command{
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
	}
}

// newPluginsPortsCmd returns `elsereno plugins ports`. v1.40+
// emits a port → []plugin map so operators can answer
// "which plugin(s) claim port 502?" without grepping
// plugins list. Default output is human-readable text;
// --json emits the map as JSON for scripting.
//
// Same-port collisions (rare but legal — IEC 61850 MMS shares
// port 102 with S7) list every claiming plugin.
func newPluginsPortsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ports",
		Short: "Emit the port → plugins map (port-to-plugin reverse index)",
		Long: `ports lists every plugin's well-known TCP/UDP port,
grouped by port number. Useful when:

  - you see a port in a discovery sweep + want to know which
    elsereno plugin to point at it via ` + "`scan --plugin <name>`" + ` or
    ` + "`fingerprint validate --plugin <name>`" + `,
  - you're scripting a pre-flight that filters captured
    NDJSON by port (some operators run elsereno in series
    with nmap-discovery + want to map nmap's port hits to
    plugin names).

Default output is plain-text "port  plugin1, plugin2, …" lines.
--json emits the map as JSON for piping into jq.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			byPort := buildPluginsByPort(core.RegisteredPlugins())
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(byPort)
			}
			ports := make([]int, 0, len(byPort))
			for p := range byPort {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			for _, port := range ports {
				cmd.Printf("%5d  %v\n", port, byPort[port])
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the port → plugins map as JSON")
	return cmd
}

// buildPluginsByPort produces a map from port number to a
// sorted list of plugin names that claim that port. Pulled
// out so the unit tests can exercise the grouping logic
// without spinning up cobra.
//
// Plugins with DefaultPort==0 are skipped (some plugins are
// transport-agnostic — atmodem doesn't have a port).
func buildPluginsByPort(plugins []core.Plugin) map[int][]string {
	out := make(map[int][]string, len(plugins))
	for _, p := range plugins {
		if p.DefaultPort == 0 {
			continue
		}
		port := int(p.DefaultPort)
		out[port] = append(out[port], p.Name)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}
