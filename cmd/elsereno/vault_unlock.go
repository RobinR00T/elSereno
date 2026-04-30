package main

// vault_unlock.go is the shared helper for verbs that need an
// unlocked vault. Lives outside cmd_serve.go so the mini build
// (which excludes serve) keeps the helper available for backup
// + creds + future verbs.
//
// Originally defined in cmd_serve.go; extracted in v1.29 chunk 1
// when cmd_serve.go got the `//go:build !mini` tag.

import (
	"errors"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
)

// unlockVault opens the on-disk vault + unlocks it via the
// passphrase either from passphraseFile (when non-empty; ADR-026
// / PITF-016) or by prompting. Returns the unlocked Vault on
// success.
func unlockVault(cmd *cobra.Command, passphraseFile string) (*creds.Vault, error) {
	v, _, err := loadVault(cmd.Context())
	if err != nil {
		return nil, err
	}
	pp, err := readPassphraseFromFileOrPrompt(cmd, passphraseFile, "Vault passphrase: ")
	if err != nil {
		return nil, fail(core.ExitUsage, err)
	}
	if err := v.Unlock(cmd.Context(), pp); err != nil {
		if errors.Is(err, creds.ErrBadPassphrase) {
			return nil, fail(core.ExitNoPerm, err)
		}
		return nil, fail(core.ExitSoftware, err)
	}
	return v, nil
}
