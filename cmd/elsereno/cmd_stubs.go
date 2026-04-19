package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// newStubCmds returns the set of verbs that are declared but not yet
// implemented. Each exits with EX_TEMPFAIL (75) and a clear message.
// Real implementations arrive in later F1 chunks (db, audit, vault,
// creds, token, serve, scan) and F2+ (repl, proxy, triage, diff,
// explain, why, lint, fmt).
func newStubCmds() []*cobra.Command {
	stubs := []struct {
		name, short string
	}{
		{"init", "Interactive first-run wizard (planned)"},
		{"db", "Database operations: migrate, status, verify, backup, reset (planned)"},
		{"audit", "Audit-log operations: verify, purge, compact (planned)"},
		{"vault", "Vault operations: init, unlock, lock, status (planned)"},
		{"creds", "Credential operations: store, list, show, rotate, purge (planned)"},
		{"token", "Web-token operations: rotate, show (planned)"},
		{"serve", "Start the HTTP dashboard (planned)"},
		{"scan", "Run a scan against targets (planned)"},
		{"repl", "Interactive protocol REPL (planned)"},
		{"proxy", "Protocol-aware interception proxy (planned)"},
		{"triage", "Group findings into quick-wins and strategic buckets (planned)"},
		{"diff", "Compare two runs (planned)"},
		{"explain", "Explain a finding's score factors (planned)"},
		{"why", "Explain why a target was scored as it was (planned)"},
		{"lint", "Validate elsereno.yaml and scope.yaml (planned)"},
		{"fmt", "Reformat elsereno.yaml and scope.yaml (planned)"},
		{"completion", "Generate shell completions (built-in via cobra in chunk 2)"},
		{"gen-man", "Generate man1 pages via cobra/doc (chunk 2)"},
	}
	out := make([]*cobra.Command, 0, len(stubs))
	for _, s := range stubs {
		s := s
		out = append(out, &cobra.Command{
			Use:   s.name,
			Short: s.short,
			RunE: func(_ *cobra.Command, _ []string) error {
				return fail(core.ExitTempFail, fmt.Errorf("%q is planned for a later phase", s.name))
			},
		})
	}
	return out
}
