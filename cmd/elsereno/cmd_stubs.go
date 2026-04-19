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
		{"token", "Web-token operations: rotate, show (planned — requires live DB)"},
		{"repl", "Interactive protocol REPL (planned)"},
		{"proxy", "Protocol-aware interception proxy (planned)"},
		{"diff", "Compare two runs (planned)"},
		{"completion", "Generate shell completions (use `elsereno --help` until cobra's generator is wired)"},
		{"gen-man", "Generate man1 pages via cobra/doc (chunk 3+)"},
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
