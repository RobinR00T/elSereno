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
	cswrite "local/elsereno/offensive/write/codesys"
	finswrite "local/elsereno/offensive/write/finsudp"
	gewrite "local/elsereno/offensive/write/gesrtp"
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
	areas          []string
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
	cmd.Flags().StringSliceVar(&f.areas, "fins-area", nil,
		"optionally narrow an allowed Memory Area Write to specific memory "+
			"area codes (byte, decimal or 0x..; e.g. 0x82 DM, 0xB0 CIO). "+
			"Repeatable. Must match the `proxy listen --fins-area` set.")
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
	areas, err := parseFINSAreas(f.areas)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	mut := finswrite.SessionMutation(f.target, allowed, areas)
	cmd.Printf("Protocol:     finsudp\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Commands:     %s\n", strings.Join(f.commands, " "))
	if len(f.areas) > 0 {
		cmd.Printf("Areas:        %s\n", strings.Join(f.areas, " "))
	}
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
	return maybeMintToken(cmd, mut, f.ppFile)
}

// ---- slmp ----------------------------------------------------------

type slmpProxyFlags struct {
	target, ppFile string
	commands       []string
	devices        []string
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
	cmd.Flags().StringSliceVar(&f.devices, "slmp-device", nil,
		"optionally narrow an allowed Device Write Batch (subcommand "+
			"0x0000) to specific device codes (byte, decimal or 0x..; e.g. "+
			"0xA8 D, 0x90 M). Repeatable. Must match `proxy listen "+
			"--slmp-device`.")
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
	devices, err := parseSLMPDevices(f.devices)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	mut := slmpwrite.SessionMutation(f.target, allowed, devices)
	cmd.Printf("Protocol:     slmp\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Commands:     %s\n", strings.Join(f.commands, " "))
	if len(f.devices) > 0 {
		cmd.Printf("Devices:      %s\n", strings.Join(f.devices, " "))
	}
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
	return maybeMintToken(cmd, mut, f.ppFile)
}

// ---- gesrtp -------------------------------------------------------

type gesrtpProxyFlags struct {
	target, ppFile string
	services       []string
}

func newWriteGESRTPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gesrtp",
		Short: "GE-SRTP write-gated proxy (proxy-dry-run derives the session confirm-token)",
	}
	cmd.AddCommand(newWriteGESRTPProxyDryRunCmd())
	return cmd
}

func newWriteGESRTPProxyDryRunCmd() *cobra.Command {
	var f gesrtpProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run: derive the confirm-token for `proxy listen --plugin gesrtp`",
		Long: `Takes an SRTP service-code allowlist and prints the canonical
SessionMutation + PayloadHash, and (with --vault-passphrase-file) the
expected confirm-token.

Read services always pass the gate; only the mutating services listed
here are admitted. Example: 0x07 WRITE_SYS_MEM, 0x23 SET_PLC_RUN.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteGESRTPProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the SRTP device we'll proxy to)")
	cmd.Flags().StringSliceVar(&f.services, "gesrtp-service", nil,
		"SRTP service-request code(s) to allow (byte, decimal or 0x..; "+
			"e.g. 0x07 WRITE_SYS_MEM). Repeatable.")
	addPassphraseFileFlag(cmd, &f.ppFile)
	return cmd
}

func runWriteGESRTPProxyDryRun(cmd *cobra.Command, f gesrtpProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.services) == 0 {
		return fail(core.ExitUsage, errors.New("--gesrtp-service is required (repeatable)"))
	}
	allowed := make([]gewrite.AllowedService, 0, len(f.services))
	for _, raw := range f.services {
		v, err := strconv.ParseUint(strings.TrimSpace(raw), 0, 8)
		if err != nil {
			return fail(core.ExitUsage, fmt.Errorf("--gesrtp-service %q: %w", raw, err))
		}
		// #nosec G115 -- ParseUint bitSize=8 bounds v to a byte.
		allowed = append(allowed, gewrite.AllowedService{Code: byte(v)})
	}
	mut := gewrite.SessionMutation(f.target, allowed)
	cmd.Printf("Protocol:     gesrtp\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Services:     %s\n", strings.Join(f.services, " "))
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
	return maybeMintToken(cmd, mut, f.ppFile)
}

// ---- codesys ------------------------------------------------------

type codesysProxyFlags struct {
	target, ppFile string
	commands       []string
}

func newWriteCoDeSysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "codesys",
		Short: "CODESYS v3 write-gated proxy (proxy-dry-run derives the session confirm-token)",
	}
	cmd.AddCommand(newWriteCoDeSysProxyDryRunCmd())
	return cmd
}

func newWriteCoDeSysProxyDryRunCmd() *cobra.Command {
	var f codesysProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run: derive the confirm-token for `proxy listen --plugin codesys`",
		Long: `Takes a CODESYS L7 command allowlist (SERVICE:CMD byte pairs) and
prints the canonical SessionMutation + PayloadHash, and (with
--vault-passphrase-file) the expected confirm-token.

Reads (handshake, status, variable reads) always pass; only the
mutating commands listed here are admitted. Example: 0x02:0x10
CmpApp/Start, 0x02:0x11 CmpApp/Stop, 0x09:0x06 CmpIecVarAccess/WriteVars.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteCoDeSysProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the CODESYS device we'll proxy to)")
	cmd.Flags().StringSliceVar(&f.commands, "codesys-command", nil,
		"CODESYS L7 command(s) to allow as SERVICE:CMD byte pairs (decimal "+
			"or 0x..; e.g. 0x02:0x10 CmpApp/Start). Repeatable. Must match "+
			"the `proxy listen --codesys-command` set.")
	addPassphraseFileFlag(cmd, &f.ppFile)
	return cmd
}

func runWriteCoDeSysProxyDryRun(cmd *cobra.Command, f codesysProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	if len(f.commands) == 0 {
		return fail(core.ExitUsage, errors.New("--codesys-command is required (repeatable; SERVICE:CMD)"))
	}
	allowed := make([]cswrite.AllowedCommand, 0, len(f.commands))
	for _, raw := range f.commands {
		c, err := parseCoDeSysCommand(raw)
		if err != nil {
			return fail(core.ExitUsage, err)
		}
		allowed = append(allowed, c)
	}
	mut := cswrite.SessionMutation(f.target, allowed)
	cmd.Printf("Protocol:     codesys\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", f.target)
	cmd.Printf("Commands:     %s\n", strings.Join(f.commands, " "))
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
	return maybeMintToken(cmd, mut, f.ppFile)
}
