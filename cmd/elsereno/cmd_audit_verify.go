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

// auditMACKeyInfo is the HKDF domain-separation label for the audit
// chain's HMAC key (ADR-017 style, cf. "elsereno/csrf/v1"). Kept stable
// so a chain written by one build verifies under the next. Defined in
// the default-build file so both `verify-file` and the offensive write
// runtime derive the same key.
const auditMACKeyInfo = "elsereno/audit/hmac/v1"

// newAuditVerifyFileCmd returns `elsereno audit verify-file`, the
// operator-facing walk over the file-backed audit chain at
// ~/.elsereno/audit.jsonl (or an operator-supplied path). Returns
// exit 0 when every entry's id + prev_hash + entry_hash verifies;
// exits with ExitError and a typed audit.ErrChainBroken on the
// first mismatch.
func newAuditVerifyFileCmd() *cobra.Command {
	var path, ppFile string
	var strict bool
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
			// Offensive write operations key their audit entries with a
			// vault-derived HMAC. Verifying those needs the same key, so
			// unlock the vault when a passphrase file is supplied.
			// Without it we can only check unkeyed (SHA-256) entries.
			if ppFile != "" {
				v, err := unlockVault(cmd, ppFile)
				if err != nil {
					return fail(core.ExitConfig, fmt.Errorf("audit verify-file: unlock vault: %w", err))
				}
				defer v.Lock()
				macKey := make([]byte, 32)
				if err := v.Derive(auditMACKeyInfo, macKey); err != nil {
					return fail(core.ExitSoftware, fmt.Errorf("audit verify-file: derive key: %w", err))
				}
				verify := audit.VerifyFileKeyed
				label := "keyed"
				if strict {
					// Strict mode rejects any unkeyed (SHA-256) entry,
					// closing the downgrade attack on the tail (PITF-108).
					// Only sound when every append was keyed.
					verify = audit.VerifyFileKeyedStrict
					label = "keyed, strict"
				}
				if err := verify(path, macKey); err != nil {
					return fail(core.ExitError, fmt.Errorf("audit verify-file: %w", err))
				}
				cmd.Printf("audit chain OK (%s): %s (%d bytes)\n", label, path, info.Size())
				return nil
			}
			if strict {
				return fail(core.ExitUsage, fmt.Errorf("audit verify-file: --strict requires --vault-passphrase-file (strict mode verifies every entry by HMAC)"))
			}
			if err := audit.VerifyFile(path); err != nil {
				return fail(core.ExitError, fmt.Errorf("audit verify-file: %w (if the log has keyed entries, pass --vault-passphrase-file)", err))
			}
			cmd.Printf("audit chain OK: %s (%d bytes)\n", path, info.Size())
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "audit log path (default ~/.elsereno/audit.jsonl)")
	cmd.Flags().BoolVar(&strict, "strict", false, "require every entry to be keyed (HMAC); rejects a downgraded unkeyed tail (PITF-108)")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}
