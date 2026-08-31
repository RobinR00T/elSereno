//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	finswrite "local/elsereno/offensive/write/finsudp"
	slmpwrite "local/elsereno/offensive/write/slmp"
)

// This file adds the proxy-session dry-run subcommands that mint the
// confirm-token for the two legacy-ICS write-gated proxies wired in
// cmd_proxy_offensive.go (finsudp, slmp). Without them the operator
// could select `proxy listen --plugin finsudp/slmp` but had no way to
// derive the ADR-039 token the handler's Authorise() demands.

// ---- finsudp -------------------------------------------------------

type finsProxyFlags struct {
	target, ppFile string
	commands       []string
}

func newWriteFINSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "finsudp",
		Short: "Omron FINS write-gated proxy (proxy-dry-run derives the session confirm-token)",
	}
	cmd.AddCommand(newWriteFINSProxyDryRunCmd())
	return cmd
}

func newWriteFINSProxyDryRunCmd() *cobra.Command {
	var f finsProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run: derive the confirm-token for `proxy listen --plugin finsudp`",
		Long: `Takes a FINS command allowlist (MRC:SRC byte pairs) and prints:
  - the canonical SessionMutation
  - the PayloadHash (sorted allowlist + target, SHA-256)
  - (if --vault-passphrase-file) the expected confirm-token

Reads always pass the gate; only the mutating commands listed here
are admitted. Example: 0x01:0x02 (Memory Area Write), 0x04:0x01 (RUN).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteFINSProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the FINS device we'll proxy to)")
	cmd.Flags().StringSliceVar(&f.commands, "fins-command", nil,
		"FINS command(s) to allow as MRC:SRC byte pairs (decimal or 0x..; "+
			"e.g. 0x01:0x02 Memory Area Write). Repeatable.")
	addPassphraseFileFlag(cmd, &f.ppFile)
	return cmd
}

func runWriteFINSProxyDryRun(cmd *cobra.Command, f finsProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.commands) == 0 {
		return fail(core.ExitUsage, errors.New("--fins-command is required (repeatable; MRC:SRC)"))
	}
	allowed := make([]finswrite.AllowedCommand, 0, len(f.commands))
	for _, raw := range f.commands {
		c, err := parseFINSCommand(raw)
		if err != nil {
			return fail(core.ExitUsage, err)
		}
		allowed = append(allowed, c)
	}
	mut := finswrite.SessionMutation(f.target, allowed)
	cmd.Printf("Protocol:     finsudp\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Commands:     %s\n", strings.Join(f.commands, " "))
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
	return maybeMintToken(cmd, mut, f.ppFile)
}

// ---- slmp ----------------------------------------------------------

type slmpProxyFlags struct {
	target, ppFile string
	commands       []string
}

func newWriteSLMPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "slmp",
		Short: "MELSEC SLMP write-gated proxy (proxy-dry-run derives the session confirm-token)",
	}
	cmd.AddCommand(newWriteSLMPProxyDryRunCmd())
	return cmd
}

func newWriteSLMPProxyDryRunCmd() *cobra.Command {
	var f slmpProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run: derive the confirm-token for `proxy listen --plugin slmp`",
		Long: `Takes an SLMP command-code allowlist and prints:
  - the canonical SessionMutation
  - the PayloadHash (sorted allowlist + target, SHA-256)
  - (if --vault-passphrase-file) the expected confirm-token

Reads always pass the gate; only the mutating commands listed here
are admitted. Example: 0x1401 (Device Write Batch), 0x1002 (Remote Stop).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteSLMPProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the SLMP device we'll proxy to)")
	cmd.Flags().StringSliceVar(&f.commands, "slmp-command", nil,
		"SLMP command code(s) to allow (uint16, decimal or 0x..; "+
			"e.g. 0x1401 Device Write Batch). Repeatable.")
	addPassphraseFileFlag(cmd, &f.ppFile)
	return cmd
}

// parseSLMPCommand parses one --slmp-command value (uint16, decimal
// or 0x-hex) into an AllowedCommand.
func parseSLMPCommand(s string) (slmpwrite.AllowedCommand, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 16)
	if err != nil {
		return slmpwrite.AllowedCommand{}, fmt.Errorf("--slmp-command %q: %w", s, err)
	}
	// #nosec G115 -- ParseUint bitSize=16 bounds v to a uint16.
	return slmpwrite.AllowedCommand{Command: uint16(v)}, nil
}

func runWriteSLMPProxyDryRun(cmd *cobra.Command, f slmpProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.commands) == 0 {
		return fail(core.ExitUsage, errors.New("--slmp-command is required (repeatable)"))
	}
	allowed := make([]slmpwrite.AllowedCommand, 0, len(f.commands))
	for _, raw := range f.commands {
		c, err := parseSLMPCommand(raw)
		if err != nil {
			return fail(core.ExitUsage, err)
		}
		allowed = append(allowed, c)
	}
	mut := slmpwrite.SessionMutation(f.target, allowed)
	cmd.Printf("Protocol:     slmp\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Commands:     %s\n", strings.Join(f.commands, " "))
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
	return maybeMintToken(cmd, mut, f.ppFile)
}
