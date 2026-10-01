package main

import (
	"encoding/json"
	"sort"

	"github.com/spf13/cobra"

	"local/elsereno/internal/standards"
)

// newStandardsCmd prints the protocol-to-standard-vulnerability catalog, so
// a run's findings can be audited against the standard (see
// docs/standards/nist-sp800-82r4.md). Findings in the ndjson output carry
// the same references under "standards".
func newStandardsCmd() *cobra.Command {
	var protocol string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "standards",
		Short: "Show which standard vulnerabilities each protocol's findings evidence",
		Long: `Prints the mapping from elSereno protocol plugins to the external
security-standard vulnerabilities their findings evidence (currently NIST
SP 800-82 Rev. 4; see docs/standards/nist-sp800-82r4.md). Findings in the
ndjson output carry the same references under "standards", so a run is
auditable against the standard.

Examples:

  elsereno standards
  elsereno standards --protocol s7-exposure --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStandards(cmd, protocol, jsonOut)
		},
	}
	cmd.Flags().StringVar(&protocol, "protocol", "", "show only this protocol's mapping")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the catalog as JSON")
	return cmd
}

func runStandards(cmd *cobra.Command, protocol string, jsonOut bool) error {
	catalog := map[string][]standards.Ref{}
	if protocol != "" {
		if refs := standards.ForProtocol(protocol); refs != nil {
			catalog[protocol] = refs
		}
	} else {
		for _, p := range standards.Protocols() {
			catalog[p] = standards.ForProtocol(p)
		}
	}

	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(catalog)
	}

	names := make([]string, 0, len(catalog))
	for p := range catalog {
		names = append(names, p)
	}
	sort.Strings(names)
	if len(names) == 0 {
		cmd.Println("No standards mapping for that protocol.")
		return nil
	}
	for _, p := range names {
		cmd.Printf("%s\n", p)
		for _, r := range catalog[p] {
			cmd.Printf("    %s %s: %s\n", r.Standard, r.Table, r.Vuln)
		}
	}
	return nil
}
