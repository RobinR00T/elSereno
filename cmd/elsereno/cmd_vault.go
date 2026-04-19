package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
)

func newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the encrypted credential vault",
	}
	cmd.AddCommand(newVaultInitCmd())
	cmd.AddCommand(newVaultUnlockCmd())
	cmd.AddCommand(newVaultLockCmd())
	cmd.AddCommand(newVaultStatusCmd())
	return cmd
}

func newVaultInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a new encrypted vault",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := creds.DefaultVaultPath()
			if err != nil {
				return fail(core.ExitOSErr, err)
			}
			pp, err := readPassphrase(cmd, "Vault passphrase (not echoed): ")
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			confirm, err := readPassphrase(cmd, "Confirm passphrase: ")
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			if string(pp) != string(confirm) {
				return fail(core.ExitUsage, fmt.Errorf("passphrases do not match"))
			}
			v := creds.New()
			if err := v.InitToFile(cmd.Context(), pp, path); err != nil {
				if errors.Is(err, creds.ErrFileExists) {
					return fail(core.ExitUsage, fmt.Errorf("%s already exists; delete or move it to re-init", path))
				}
				return fail(core.ExitSoftware, err)
			}
			cmd.Printf("vault created: %s\n", path)
			return nil
		},
	}
}

func newVaultUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Decrypt the vault for subsequent operations (best-effort in CLI context)",
		Long: "unlock is conceptually a long-lived server operation (see " +
			"serve). In the one-shot CLI, each command re-unlocks via the " +
			"passphrase. This verb verifies that the vault is present and " +
			"the passphrase is correct.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, _, err := loadVault(cmd.Context())
			if err != nil {
				return err
			}
			pp, err := readPassphrase(cmd, "Vault passphrase: ")
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			if err := v.Unlock(cmd.Context(), pp); err != nil {
				return fail(core.ExitNoPerm, err)
			}
			cmd.Println("vault unlocked (this shell's one-shot context)")
			return nil
		},
	}
}

func newVaultLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Zeroise any in-process vault state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// In the one-shot CLI there is no long-lived state to zeroise,
			// but the verb is still here so scripts can invoke it.
			cmd.Println("vault state zeroised")
			return nil
		},
	}
}

func newVaultStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the vault exists and is accessible",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := creds.DefaultVaultPath()
			if err != nil {
				return fail(core.ExitOSErr, err)
			}
			if _, err := os.Stat(path); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					cmd.Printf("vault: not initialised (%s)\n", path)
					cmd.Println("hint: elsereno vault init")
					return nil
				}
				return fail(core.ExitOSErr, err)
			}
			cmd.Printf("vault: initialised (%s)\n", path)
			return nil
		},
	}
}

// loadVault reads the file-backed vault but does not unlock it.
// Callers must call v.Unlock(ctx, passphrase) after.
func loadVault(_ context.Context) (*creds.Vault, string, error) {
	path, err := creds.DefaultVaultPath()
	if err != nil {
		return nil, "", fail(core.ExitOSErr, err)
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, path, fail(core.ExitUsage, fmt.Errorf("vault not initialised (run `elsereno vault init`)"))
		}
		return nil, path, fail(core.ExitOSErr, err)
	}
	v := creds.New()
	if err := v.LoadFromFile(path); err != nil {
		return nil, path, fail(core.ExitConfig, err)
	}
	return v, path, nil
}

// readPassphrase reads a line from stdin with echo disabled. If stdin
// is not a TTY (piped input), it reads without the "not echoed"
// suffix to support CI/cron patterns — but still never logs it.
func readPassphrase(cmd *cobra.Command, prompt string) ([]byte, error) {
	// term.IsTerminal expects int; os.Stdin.Fd returns uintptr. The
	// cast is safe on every supported platform because file descriptors
	// fit in int (POSIX guarantees it; Windows uses HANDLE but the
	// term package does its own conversion there).
	fd := int(os.Stdin.Fd()) // #nosec G115 -- fd fits in int
	if term.IsTerminal(fd) {
		_, _ = cmd.ErrOrStderr().Write([]byte(prompt))
		pp, err := term.ReadPassword(fd)
		_, _ = cmd.ErrOrStderr().Write([]byte("\n"))
		if err != nil {
			return nil, err
		}
		return pp, nil
	}
	// Non-TTY (CI/cron). Let the operator pipe in a passphrase.
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n == 0 || err != nil {
			break
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	if len(line) == 0 {
		return nil, fmt.Errorf("empty passphrase on stdin")
	}
	// ADR-026: warn if ELSERENO_VAULT_PASSPHRASE was set AND we're in
	// a TTY (mistaken interactive use). Checked up-stream by wrappers.
	return line, nil
}
