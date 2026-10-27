package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/standards"
)

// newStandardsCmd prints the protocol-to-standard-vulnerability catalog, so
// a run's findings can be audited against the standard (see
// docs/standards/nist-sp800-82r4.md). Findings in the ndjson output carry
// the same references under "standards".
func newStandardsCmd() *cobra.Command {
	var protocol, standard string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "standards",
		Short: "Show which standard vulnerabilities each protocol's findings evidence",
		Long: `Prints the mapping from elSereno protocol plugins to the external
security references their findings evidence, from three sources:

  nist        NIST SP 800-82 Rev. 4 (docs/standards/nist-sp800-82r4.md)
  attack-ics  MITRE ATT&CK for ICS v20 techniques (docs/standards/mitre-attack-ics.md)
  iec62443    ISA/IEC 62443-3-3 system requirements (docs/standards/iec62443-3-3.md)

Findings in every output (ndjson, HTML, CEF, syslog, STIX, tickets) carry
the same references under "standards", so a run is auditable against each
of them. The mapping is elSereno's reading; MITRE, NIST, ISA and IEC have
not reviewed it. "it-management" is not a plugin: it is the exposure
category plaintext-check and discover --it-ports report for SSH, RDP, SMB,
MS SQL and the other IT management services.

Examples:

  elsereno standards
  elsereno standards --standard attack-ics
  elsereno standards --protocol s7-exposure --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStandards(cmd, protocol, standard, jsonOut)
		},
	}
	cmd.Flags().StringVar(&protocol, "protocol", "", "show only this protocol's mapping")
	cmd.Flags().StringVar(&standard, "standard", "", "show only one standard: "+strings.Join(standards.Keys(), " | "))
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the catalog as JSON")
	return cmd
}

func runStandards(cmd *cobra.Command, protocol, standard string, jsonOut bool) error {
	if standard != "" && !slices.Contains(standards.Keys(), standard) {
		return fail(core.ExitUsage, fmt.Errorf("--standard %q: want one of %s", standard, strings.Join(standards.Keys(), ", ")))
	}
	lookup := func(p string) []standards.Ref {
		if standard != "" {
			return standards.ForProtocolIn(standard, p)
		}
		return standards.ForProtocol(p)
	}
	catalog := map[string][]standards.Ref{}
	protocols := standards.Protocols()
	if protocol != "" {
		protocols = []string{protocol}
	}
	for _, p := range protocols {
		if refs := lookup(p); refs != nil {
			catalog[p] = refs
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
