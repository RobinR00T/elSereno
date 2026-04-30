package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit-log operations",
	}
	cmd.AddCommand(newAuditVerifyCmd())
	cmd.AddCommand(newAuditVerifyFileCmd())
	cmd.AddCommand(newAuditServeCmd())
	cmd.AddCommand(newAuditDestructiveCmd("purge",
		"Tombstone-purge audit entries before a cutoff (preserves chain)",
		"i-understand-this-is-forensic-data",
		"purge writer wires in with the audit subsystem (chunk 3+)"))
	cmd.AddCommand(newAuditDestructiveCmd("compact",
		"Hard-delete audit entries before a cutoff (inserts chain_rebase marker)",
		"i-break-the-chain",
		"compact writer wires in with the audit subsystem (chunk 3+)"))
	return cmd
}

func newAuditVerifyCmd() *cobra.Command {
	var tail int
	var since string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit hash chain (tail or full)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := loadConfig()
			if err != nil {
				return fail(core.ExitConfig, err)
			}
			limit := tail
			if limit <= 0 {
				limit = cfg.ReadyZ.AuditTailEntries
			}
			_ = since
			_ = jsonOut
			cmd.Printf("audit verify: tail=%d (no live DB connection; empty chain assumed)\n", limit)
			cmd.Println("hint: set DATABASE_URL and run `elsereno db verify` first")
			return fail(core.ExitUnavail, fmt.Errorf("live audit verification arrives with the audit writer"))
		},
	}
	cmd.Flags().IntVar(&tail, "tail", 0, "number of trailing entries to verify (default readyz.audit_tail_entries)")
	cmd.Flags().StringVar(&since, "since", "", "only verify entries with occurred_at >= this RFC3339 timestamp")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit a structured JSON report")
	return cmd
}

// newAuditDestructiveCmd is the common scaffold for `audit purge` and
// `audit compact`. Both require a `--before` cutoff, a verb-specific
// risk flag, and `--yes` for batch. Extracted to avoid dupl.
func newAuditDestructiveCmd(verb, short, riskFlag, pendingMsg string) *cobra.Command {
	var before string
	var yes, riskAck bool
	cmd := &cobra.Command{
		Use:   verb,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			if !riskAck {
				return fail(core.ExitUsage, fmt.Errorf("required flag --%s missing", riskFlag))
			}
			if before == "" {
				return fail(core.ExitUsage, fmt.Errorf("--before is required (RFC3339)"))
			}
			if !yes {
				return fail(core.ExitUsage, fmt.Errorf("pass --yes for non-interactive runs"))
			}
			return fail(core.ExitUnavail, fmt.Errorf("%s", pendingMsg))
		},
	}
	cmd.Flags().StringVar(&before, "before", "", "RFC3339 cutoff (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip interactive confirmation (batch mode)")
	cmd.Flags().BoolVar(&riskAck, riskFlag, false, "required acknowledgement")
	return cmd
}
