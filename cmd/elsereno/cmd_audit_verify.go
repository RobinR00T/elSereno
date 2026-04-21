package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/core"
)

// newAuditVerifyFileCmd returns `elsereno audit verify-file`, the
// operator-facing walk over the file-backed audit chain at
// ~/.elsereno/audit.jsonl (or an operator-supplied path). Returns
// exit 0 when every entry's id + prev_hash + entry_hash verifies;
// exits with ExitError and a typed audit.ErrChainBroken on the
// first mismatch.
func newAuditVerifyFileCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "verify-file",
		Short: "Walk the file-backed audit chain (~/.elsereno/audit.jsonl)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if path == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fail(core.ExitOSErr, err)
				}
				path = filepath.Join(home, ".elsereno", "audit.jsonl")
			}
			info, err := os.Stat(path)
			switch {
			case errors.Is(err, os.ErrNotExist):
				cmd.Printf("no audit log at %s (nothing to verify)\n", path)
				return nil
			case err != nil:
				return fail(core.ExitIOErr, err)
			}
			if err := audit.VerifyFile(path); err != nil {
				return fail(core.ExitError, fmt.Errorf("audit verify-file: %w", err))
			}
			cmd.Printf("audit chain OK: %s (%d bytes)\n", path, info.Size())
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "audit log path (default ~/.elsereno/audit.jsonl)")
	return cmd
}
