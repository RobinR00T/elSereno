//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	iaxwire "local/elsereno/internal/protocols/iax2/wire"
	"local/elsereno/offensive/confirm"
	iaxwrite "local/elsereno/offensive/write/iax2"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	sipwrite "local/elsereno/offensive/write/sip"

	"local/elsereno/internal/core"
)

// ---- elsereno write sip ---------------------------------------

func newWriteSIPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sip",
		Short: "SIP method-gated proxy (dry-run derives the session confirm-token)",
		Long: `The gated SIP proxy allows only operator-listed
methods (INVITE / REGISTER / MESSAGE / SUBSCRIBE / NOTIFY / REFER /
PUBLISH / UPDATE / INFO); always-safe methods (OPTIONS / ACK / BYE
/ CANCEL / PRACK) pass unconditionally. Refused requests get a
SIP/2.0 405 Method Not Allowed with a canonical Allow: header.

Dry-run derives the session PayloadHash (deterministic SHA-256 of
the canonicalised allowlist + target) and, when --vault-passphrase-file
is supplied, the expected confirm-token the operator will paste
into the eventual proxy-run verb.`,
	}
	cmd.AddCommand(newWriteSIPDryRunCmd())
	return cmd
}

func newWriteSIPDryRunCmd() *cobra.Command {
	var target, ppFile string
	var methods []string
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			allowed := make([]sipwrite.AllowedMethod, 0, len(methods))
			for _, m := range methods {
				allowed = append(allowed, sipwrite.AllowedMethod{Method: m})
			}
			mut := sipwrite.SessionMutation(target, allowed)
			cmd.Printf("Protocol:     sip\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Allowed:      %s\n", canonMethods(methods))
			cmd.Printf("Always-safe:  OPTIONS, ACK, BYE, CANCEL, PRACK\n")
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			return maybeMintToken(cmd, mut, ppFile)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the SIP server we'll proxy to)")
	cmd.Flags().StringSliceVar(&methods, "method", nil, "one or more gated methods (repeat or comma-separated)")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}

// ---- elsereno write iax2 --------------------------------------

func newWriteIAX2Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iax2",
		Short: "IAX2 subclass-gated proxy (dry-run derives the session confirm-token)",
		Long: `The gated IAX2 proxy allows only operator-listed IAX
control subclasses (NEW / REGREQ / AUTHREP / ACCEPT); always-safe
subclasses (HANGUP / ACK / PING / PONG / LAGRQ / LAGRP / INVAL /
REGAUTH / REGACK / REGREJ / REGREL / REJECT) pass unconditionally.
Mini-frames (audio) and non-IAX full frames (Voice / DTMF / Video
/ etc.) ALWAYS pass — media is never blocked. Refused frames get a
HANGUP addressed to the client's SrcCallNum.`,
	}
	cmd.AddCommand(newWriteIAX2DryRunCmd())
	return cmd
}

func newWriteIAX2DryRunCmd() *cobra.Command {
	var target, ppFile string
	var subclasses []string
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			allowed := make([]iaxwrite.AllowedSubclass, 0, len(subclasses))
			for _, s := range subclasses {
				sub, err := iaxSubclassByName(s)
				if err != nil {
					return fail(core.ExitUsage, err)
				}
				allowed = append(allowed, iaxwrite.AllowedSubclass{Subclass: sub})
			}
			mut := iaxwrite.SessionMutation(target, allowed)
			cmd.Printf("Protocol:     iax2\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Allowed:      %s\n", canonSubclasses(subclasses))
			cmd.Printf("Always-safe:  HANGUP, ACK, PING, PONG, LAGRQ, LAGRP, INVAL, REGAUTH, REGACK, REGREJ, REGREL, REJECT\n")
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			return maybeMintToken(cmd, mut, ppFile)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the IAX2 server we'll proxy to)")
	cmd.Flags().StringSliceVar(&subclasses, "subclass", nil, "one or more gated subclasses (NEW / REGREQ / AUTHREP / ACCEPT)")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}

// ---- elsereno write pbxhttp -----------------------------------

func newWritePBXHTTPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pbxhttp",
		Short: "PBX HTTP admin-UI (method, path)-gated proxy",
		Long: `The gated HTTP admin proxy allows only operator-listed
(method, path) pairs; read-only methods (GET / HEAD / OPTIONS) pass
unconditionally. Refused requests get a 405 Method Not Allowed
when the method isn't in the allowlist, or a 403 Forbidden when
the method matches but the path doesn't. CONNECT is always
refused — the gate can't inspect tunnelled traffic.`,
	}
	cmd.AddCommand(newWritePBXHTTPDryRunCmd())
	return cmd
}

func newWritePBXHTTPDryRunCmd() *cobra.Command {
	var target, ppFile string
	var entries []string
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		Long: `--allow accepts METHOD:/path entries. Repeat the flag
or comma-separate to list multiple pairs. Method is case-folded;
path is case-sensitive (RFC 3986).`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			allowed := make([]pbxwrite.AllowedWrite, 0, len(entries))
			for _, e := range entries {
				aw, err := parseAllowEntry(e)
				if err != nil {
					return fail(core.ExitUsage, err)
				}
				allowed = append(allowed, aw)
			}
			mut := pbxwrite.SessionMutation(target, allowed)
			cmd.Printf("Protocol:     pbxhttp\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Allowed:      %s\n", canonPBXEntries(allowed))
			cmd.Printf("Always-safe:  GET, HEAD, OPTIONS\n")
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			return maybeMintToken(cmd, mut, ppFile)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the HTTP(S) PBX admin server)")
	cmd.Flags().StringSliceVar(&entries, "allow", nil, "one or more METHOD:/path pairs (repeat or comma-separated)")
	addPassphraseFileFlag(cmd, &ppFile)
	return cmd
}

// ---- shared helpers -------------------------------------------

// maybeMintToken derives + prints the expected confirm-token when
// the operator supplied --vault-passphrase-file. Missing file
// leaves the token unprinted; the operator can mint it via any
// other vault-backed offensive verb.
func maybeMintToken(cmd *cobra.Command, mut confirm.Mutation, ppFile string) error {
	if ppFile == "" {
		cmd.Printf("\n(no --vault-passphrase-file supplied; confirm-token not minted. Re-run with --vault-passphrase-file <0600 path> to derive it.)\n")
		return nil
	}
	rt, err := newOffensiveRuntime(cmd, ppFile)
	if err != nil {
		return err
	}
	defer rt.Close()
	tok, err := confirm.ExpectedToken(mut, rt.Vault)
	if err != nil {
		return fail(core.ExitError, fmt.Errorf("mint token: %w", err))
	}
	cmd.Printf("\nConfirm-token: %s\n", tok)
	cmd.Printf("Use with --accept-writes --confirm-target %s --confirm-token %s\n", mut.Target, tok)
	return nil
}

// canonMethods uppercases + sorts + dedupes a method list for
// operator-readable output. Matches sipwrite.AllowlistHash's
// canonicalisation.
func canonMethods(methods []string) string {
	if len(methods) == 0 {
		return "(none — no gated methods allowed)"
	}
	set := map[string]struct{}{}
	for _, m := range methods {
		set[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// canonSubclasses returns the human-readable sorted subclass list.
func canonSubclasses(subs []string) string {
	if len(subs) == 0 {
		return "(none — no gated subclasses allowed)"
	}
	set := map[string]struct{}{}
	for _, s := range subs {
		set[strings.ToUpper(strings.TrimSpace(s))] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// canonPBXEntries returns the sorted "METHOD /path" list for the
// pbxhttp allowlist.
func canonPBXEntries(allowed []pbxwrite.AllowedWrite) string {
	if len(allowed) == 0 {
		return "(none — no gated methods allowed)"
	}
	keys := make([]string, 0, len(allowed))
	for _, a := range allowed {
		keys = append(keys, strings.ToUpper(strings.TrimSpace(a.Method))+" "+strings.TrimSpace(a.Path))
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// parseAllowEntry splits a METHOD:/path flag value. The first
// colon separates; "/path" starts after it. Examples:
//
//	POST:/admin/config.php
//	DELETE:/admin/user/42
//	PUT:/api/v1/extensions
func parseAllowEntry(entry string) (pbxwrite.AllowedWrite, error) {
	entry = strings.TrimSpace(entry)
	idx := strings.IndexByte(entry, ':')
	if idx <= 0 || idx >= len(entry)-1 {
		return pbxwrite.AllowedWrite{}, fmt.Errorf("--allow %q: want METHOD:/path (e.g. POST:/admin/config.php)", entry)
	}
	method := strings.ToUpper(strings.TrimSpace(entry[:idx]))
	path := strings.TrimSpace(entry[idx+1:])
	if !strings.HasPrefix(path, "/") {
		return pbxwrite.AllowedWrite{}, fmt.Errorf("--allow %q: path must start with /", entry)
	}
	return pbxwrite.AllowedWrite{Method: method, Path: path}, nil
}

// iaxSubclassByName maps an operator-supplied subclass name to
// the wire constant. Case-insensitive; supports the short names
// (NEW, REGREQ, AUTHREP, ACCEPT) we document in the help text.
func iaxSubclassByName(name string) (iaxwire.IAXSubclass, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "NEW":
		return iaxwire.IAXNew, nil
	case "REGREQ":
		return iaxwire.IAXRegreq, nil
	case "AUTHREP":
		return iaxwire.IAXAuthRep, nil
	case "ACCEPT":
		return iaxwire.IAXAccept, nil
	}
	return 0, fmt.Errorf("--subclass %q: want one of NEW / REGREQ / AUTHREP / ACCEPT", name)
}
