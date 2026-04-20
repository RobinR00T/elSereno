package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"local/elsereno/internal/backup"
	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Encrypted backup + restore (vault-keyed AES-256-GCM)",
		Long: "Backups are tamper-evident: AES-256-GCM envelope with HKDF key\n" +
			"derived from the unlocked vault (info=\"elsereno/backup/v1\") +\n" +
			"per-archive salt. A restore requires the same vault master.\n" +
			"See `.context/threat-model/vault-audit.md` for the full policy.",
	}
	cmd.AddCommand(newBackupCreateCmd())
	cmd.AddCommand(newBackupRestoreCmd())
	cmd.AddCommand(newBackupInspectCmd())
	return cmd
}

func newBackupCreateCmd() *cobra.Command {
	var out, ppFile string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an encrypted backup of the vault file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out == "" {
				return fail(core.ExitUsage, errors.New("--out <path> is required"))
			}
			v, err := unlockVault(cmd, ppFile)
			if err != nil {
				return err
			}
			vaultPath, err := creds.DefaultVaultPath()
			if err != nil {
				return fail(core.ExitOSErr, err)
			}
			// #nosec G304 -- caller-controlled vault path
			body, err := os.ReadFile(vaultPath)
			if err != nil {
				return fail(core.ExitIOErr, fmt.Errorf("read vault %s: %w", vaultPath, err))
			}
			files := []backup.File{
				{Name: "vault.v1.bin", Body: body, Mode: 0o600},
			}
			// #nosec G304 -- operator-supplied output path
			f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fail(core.ExitIOErr, err)
			}
			defer func() { _ = f.Close() }()
			if err := backup.Create(f, v, files); err != nil {
				return fail(core.ExitSoftware, err)
			}
			cmd.Printf("wrote %s (%d bytes payload, envelope version %d)\n", out, len(body), backup.Version)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "out", "o", "", "output path (required, 0600)")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}

func newBackupRestoreCmd() *cobra.Command {
	var in, toDir, ppFile string
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Decrypt a backup into --to <dir>",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if in == "" || toDir == "" {
				return fail(core.ExitUsage, errors.New("--in and --to are required"))
			}
			v, err := unlockVault(cmd, ppFile)
			if err != nil {
				return err
			}
			// #nosec G304 -- operator-supplied input
			f, err := os.Open(in)
			if err != nil {
				return fail(core.ExitIOErr, err)
			}
			defer func() { _ = f.Close() }()
			files, err := backup.Restore(f, v)
			if err != nil {
				return fail(core.ExitSoftware, err)
			}
			// Refuse to overwrite an existing destination to avoid
			// a silent stomp on an existing vault. Operator must
			// create the directory beforehand.
			info, err := os.Stat(toDir)
			if err != nil {
				return fail(core.ExitUsage, fmt.Errorf("--to %s: %w", toDir, err))
			}
			if !info.IsDir() {
				return fail(core.ExitUsage, fmt.Errorf("--to %s is not a directory", toDir))
			}
			for _, bf := range files {
				dst := toDir + string(os.PathSeparator) + bf.Name
				// bf.Mode comes from a tar header we wrote on
				// `Create`; narrow to 12-bit Unix perms so
				// gosec G115 is satisfied.
				mode := os.FileMode(uint32(bf.Mode) & 0o7777) //nolint:gosec // G115 — bit-masked above
				// #nosec G304 -- caller-controlled destination
				if err := os.WriteFile(dst, bf.Body, mode); err != nil {
					return fail(core.ExitIOErr, err)
				}
				cmd.Printf("restored %s (%d bytes, mode %#o)\n", dst, len(bf.Body), mode)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&in, "in", "i", "", "encrypted backup path (required)")
	cmd.Flags().StringVar(&toDir, "to", "", "directory to extract into (required)")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}

func newBackupInspectCmd() *cobra.Command {
	var in string
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Describe an encrypted backup without decrypting (envelope metadata only)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if in == "" {
				return fail(core.ExitUsage, errors.New("--in is required"))
			}
			// #nosec G304 -- operator-supplied input
			f, err := os.Open(in)
			if err != nil {
				return fail(core.ExitIOErr, err)
			}
			defer func() { _ = f.Close() }()
			hdr := make([]byte, 4+1+backup.SaltLen+backup.NonceLen)
			n, _ := f.Read(hdr)
			if n < len(hdr) {
				return fail(core.ExitSoftware, backup.ErrTruncated)
			}
			magic := uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3])
			if magic != backup.Magic {
				return fail(core.ExitSoftware, backup.ErrBadMagic)
			}
			version := hdr[4]
			cmd.Printf("path:      %s\n", in)
			cmd.Printf("magic:     0x%08x (%s)\n", magic, magicLabel(magic))
			cmd.Printf("version:   %d\n", version)
			cmd.Printf("salt:      %x\n", hdr[5:5+backup.SaltLen])
			cmd.Printf("nonce:     %x\n", hdr[5+backup.SaltLen:])
			info, err := f.Stat()
			if err == nil {
				cmd.Printf("size:      %d bytes\n", info.Size())
				cmd.Printf("mode:      %#o\n", info.Mode().Perm())
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&in, "in", "i", "", "backup path (required)")
	return cmd
}

func magicLabel(m uint32) string {
	if m == backup.Magic {
		return "ELSB"
	}
	return "unknown"
}
