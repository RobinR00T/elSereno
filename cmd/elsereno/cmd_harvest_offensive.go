//go:build offensive

package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/offensive/harvest"
	"local/elsereno/offensive/sandbox"
)

func newHarvestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "harvest",
		Short: "Credential harvest probes (telnet / ftp / http-basic / snmp)",
	}
	cmd.AddCommand(newHarvestRunCmd("telnet", harvest.NewTelnet()))
	cmd.AddCommand(newHarvestRunCmd("ftp", harvest.NewFTP()))
	cmd.AddCommand(newHarvestRunCmd("http-basic", harvest.NewHTTPBasic()))
	cmd.AddCommand(newHarvestRunCmd("snmp", harvest.NewSNMP()))
	return cmd
}

// prober is the reduced surface of harvest.Prober that cmd relies
// on. Exists only to decouple the switch statement above from the
// concrete type, should someone test a mock in-process.
type prober interface {
	Name() string
	DefaultPort() uint16
	Probe(ctx context.Context, target string, creds []harvest.Credential) (*harvest.Result, error)
}

func newHarvestRunCmd(name string, p prober) *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use:   name,
		Short: fmt.Sprintf("Probe %s for default credentials on <target>", name),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, fmt.Errorf("--target is required (host:port)"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Install the harvest seccomp profile before any
			// network I/O. ADR-042: harvest probes must not be
			// allowed to mutate the filesystem, so the `harvest`
			// profile blocks truncate/unlink/chmod/rename family
			// syscalls (see offensive/sandbox/syscalls_linux.go).
			rt, err := newAuditOnlyRuntime()
			if err != nil {
				return err
			}
			defer rt.Close()
			if err := rt.ApplySandbox(ctx, sandbox.ProfileHarvest); err != nil {
				return fail(core.ExitSoftware, fmt.Errorf("sandbox: %w", err))
			}

			res, err := p.Probe(ctx, target, harvest.DefaultCredentials())
			switch {
			case errors.Is(err, harvest.ErrNoHit):
				cmd.Printf("NO-HIT %s %s\n", name, target)
				return nil
			case err != nil:
				return fail(core.ExitError, err)
			}
			cmd.Printf("HIT %s %s — ", name, target)
			if res.Credential.Community != "" {
				cmd.Printf("community=%q", res.Credential.Community)
			} else {
				cmd.Printf("username=%q password=%q", res.Credential.Username, res.Credential.Password)
			}
			if res.Banner != "" {
				cmd.Printf(" banner=%q", truncateBanner(res.Banner, 80))
			}
			cmd.Println()
			cmd.Println()
			cmd.Println("Discovered credentials SHOULD be stored in the vault:")
			cmd.Printf("  elsereno creds store %s-%s\n", name, target)
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "host:port to probe")
	return cmd
}

func truncateBanner(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
