package main

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
)

func newCredsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "creds",
		Short: "Manage stored credentials inside the vault",
	}
	cmd.AddCommand(newCredsStoreCmd())
	cmd.AddCommand(newCredsListCmd())
	cmd.AddCommand(newCredsShowCmd())
	cmd.AddCommand(newCredsRotateCmd())
	cmd.AddCommand(newCredsPurgeCmd())
	return cmd
}

func newCredsStoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "store <name>",
		Short: "Store a credential in the vault (reads value from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, path, err := loadVault(cmd.Context())
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
			value, err := readPassphrase(cmd, fmt.Sprintf("Value for %q (not echoed): ", args[0]))
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			if err := v.Store(cmd.Context(), args[0], value); err != nil {
				return fail(core.ExitSoftware, err)
			}
			if err := v.SaveToFile(path); err != nil {
				return fail(core.ExitIOErr, err)
			}
			cmd.Printf("stored %q in %s\n", args[0], path)
			return nil
		},
	}
}

func newCredsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the names of stored credentials",
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
			names := v.List()
			sort.Strings(names)
			for _, n := range names {
				md, err := v.Metadata(n)
				if err != nil {
					continue
				}
				cmd.Printf("%-24s created=%s", n, md.CreatedAt.Format(time.RFC3339))
				if !md.RotatedAt.IsZero() {
					cmd.Printf(" rotated=%s", md.RotatedAt.Format(time.RFC3339))
				}
				cmd.Println()
			}
			if len(names) == 0 {
				cmd.Println("(no secrets)")
			}
			return nil
		},
	}
}

func newCredsShowCmd() *cobra.Command {
	var reveal bool
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Print metadata for a credential; --reveal prints plaintext + audit entry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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
			md, err := v.Metadata(args[0])
			if err != nil {
				if errors.Is(err, creds.ErrNameNotFound) {
					return fail(core.ExitNoInput, err)
				}
				return fail(core.ExitSoftware, err)
			}
			cmd.Printf("name:       %s\n", md.Name)
			cmd.Printf("created:    %s\n", md.CreatedAt.Format(time.RFC3339))
			if !md.RotatedAt.IsZero() {
				cmd.Printf("rotated:    %s\n", md.RotatedAt.Format(time.RFC3339))
			}
			if !reveal {
				cmd.Println("hint: pass --reveal to print the plaintext (audited)")
				return nil
			}
			value, err := v.Retrieve(cmd.Context(), args[0])
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			cmd.Printf("value:      %s\n", value)
			// Audit entry for the reveal (no value captured). The audit
			// chain writer hooks in when DB is wired; for now we print
			// the intent so scripts can grep for it.
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(),
				"audit: creds_show_reveal name=%s at=%s (value not logged)\n",
				md.Name, time.Now().UTC().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().BoolVar(&reveal, "reveal", false, "also print the plaintext value (audited)")
	return cmd
}

func newCredsRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <name>",
		Short: "Replace the plaintext for a credential (reads value from stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, path, err := loadVault(cmd.Context())
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
			value, err := readPassphrase(cmd, fmt.Sprintf("New value for %q: ", args[0]))
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			if err := v.Rotate(cmd.Context(), args[0], value); err != nil {
				if errors.Is(err, creds.ErrNameNotFound) {
					return fail(core.ExitNoInput, err)
				}
				return fail(core.ExitSoftware, err)
			}
			if err := v.SaveToFile(path); err != nil {
				return fail(core.ExitIOErr, err)
			}
			cmd.Printf("rotated %q\n", args[0])
			return nil
		},
	}
}

func newCredsPurgeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "purge <name>",
		Short: "Delete a credential from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, path, err := loadVault(cmd.Context())
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
			if err := v.Purge(cmd.Context(), args[0]); err != nil {
				if errors.Is(err, creds.ErrNameNotFound) {
					return fail(core.ExitNoInput, err)
				}
				return fail(core.ExitSoftware, err)
			}
			if err := v.SaveToFile(path); err != nil {
				return fail(core.ExitIOErr, err)
			}
			cmd.Printf("purged %q\n", args[0])
			return nil
		},
	}
}
