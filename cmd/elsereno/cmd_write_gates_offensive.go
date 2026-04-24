//go:build offensive

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	iaxwire "local/elsereno/internal/protocols/iax2/wire"
	"local/elsereno/offensive/confirm"
	bacwrite "local/elsereno/offensive/write/bacnet"
	iaxwrite "local/elsereno/offensive/write/iax2"
	opwrite "local/elsereno/offensive/write/opcua"
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
	var target, ppFile, emitFile string
	var methods, toPrefixes []string
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
			prefixes := make([]sipwrite.AllowedToURIPrefix, 0, len(toPrefixes))
			for _, p := range toPrefixes {
				prefixes = append(prefixes, sipwrite.AllowedToURIPrefix{Prefix: p})
			}
			mut := sipwrite.SessionMutationWithPrefixes(target, allowed, prefixes)
			cmd.Printf("Protocol:     sip\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Allowed:      %s\n", canonMethods(methods))
			cmd.Printf("Always-safe:  OPTIONS, ACK, BYE, CANCEL, PRACK\n")
			if len(toPrefixes) > 0 {
				cmd.Printf("ToPrefixes:   %s\n", canonMethods(toPrefixes))
			} else {
				cmd.Printf("ToPrefixes:   (none — INVITE destination not constrained)\n")
			}
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileSIP(target, methods, toPrefixes))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the SIP server we'll proxy to)")
	cmd.Flags().StringSliceVar(&methods, "method", nil, "one or more gated methods (repeat or comma-separated)")
	cmd.Flags().StringSliceVar(&toPrefixes, "to-prefix", nil,
		"optional: INVITE destination allowlist — URI user-part prefixes (e.g. +34, +44). Only applies to INVITE; other methods unaffected. Toll-fraud mitigation (v1.9+).")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
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
	var target, ppFile, emitFile string
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
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileIAX2(target, subclasses))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the IAX2 server we'll proxy to)")
	cmd.Flags().StringSliceVar(&subclasses, "subclass", nil, "one or more gated subclasses (NEW / REGREQ / AUTHREP / ACCEPT)")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
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
	var target, ppFile, emitFile string
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
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFilePBXHTTP(target, entries))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the HTTP(S) PBX admin server)")
	cmd.Flags().StringSliceVar(&entries, "allow", nil, "one or more METHOD:/path pairs (repeat or comma-separated)")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
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

// ---- elsereno write opcua -------------------------------------

func newWriteOPCUACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "opcua",
		Short: "OPC UA service-TypeID + optional per-NodeId proxy-session dry-run",
		Long: `The gated OPC UA proxy authorises at service-TypeID
granularity by default (allow WriteRequest, CallRequest, etc).
Add --node-id ns=N;i=M (repeatable) to tighten the gate to
specific Object_Identifier NodeIds: a WriteRequest then passes
only when both its service TypeID is allowed AND the first
WriteValue's NodeId is in the list. Rarer NodeId encodings
(String / Guid / ByteString) are refused when per-node gating
is active — the gate fails closed.`,
	}
	cmd.AddCommand(newWriteOPCUADryRunCmd())
	return cmd
}

func newWriteOPCUADryRunCmd() *cobra.Command {
	var target, ppFile, emitFile string
	var services []uint
	var nodeIDs []string
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			svcs := make([]opwrite.AllowedService, 0, len(services))
			for _, s := range services {
				if s > 0xFFFF {
					return fail(core.ExitUsage, fmt.Errorf("--service %d: must be 0-65535", s))
				}
				svcs = append(svcs, opwrite.AllowedService{TypeID: uint16(s)})
			}
			nids := make([]opwrite.AllowedNodeID, 0, len(nodeIDs))
			for _, n := range nodeIDs {
				parsed, err := parseNodeIDFlag(n)
				if err != nil {
					return fail(core.ExitUsage, err)
				}
				nids = append(nids, parsed)
			}
			mut := opwrite.SessionMutationWithNodeIDs(target, svcs, nids)
			cmd.Printf("Protocol:     opcua\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Services:     %s\n", canonUintList(services))
			cmd.Printf("NodeIDs:      %s\n", canonNodeIDs(nids))
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileOPCUA(target, services, nodeIDs))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the OPC UA server we'll proxy to)")
	cmd.Flags().UintSliceVar(&services, "service", nil, "service TypeID(s) to allow (e.g. 673 WriteRequest, 704 CallRequest)")
	cmd.Flags().StringSliceVar(&nodeIDs, "node-id", nil, "optional NodeId(s) to restrict WriteRequests to, in ns=N;i=M form")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
	return cmd
}

// ---- elsereno write bacnet ------------------------------------

func newWriteBACnetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bacnet",
		Short: "BACnet/IP confirmed-service proxy-session dry-run",
		Long: `The gated BACnet proxy always forwards non-BACnet
traffic, unconfirmed-requests (Who-Is / I-Am / etc), acks /
errors / rejects / aborts, and confirmed-reads. Confirmed-
requests with a mutating service choice (WriteProperty,
WritePropertyMultiple, AtomicWriteFile, CreateObject,
DeleteObject, ReinitializeDevice, DeviceCommunicationControl,
LifeSafetyOperation, Add/RemoveListElement) require explicit
--service-choice allowlist entries.`,
	}
	cmd.AddCommand(newWriteBACnetDryRunCmd())
	return cmd
}

func newWriteBACnetDryRunCmd() *cobra.Command {
	var target, ppFile, emitFile string
	var serviceChoices []uint
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			svcs := make([]bacwrite.AllowedService, 0, len(serviceChoices))
			for _, s := range serviceChoices {
				if s > 0xFF {
					return fail(core.ExitUsage, fmt.Errorf("--service-choice %d: must be 0-255", s))
				}
				svcs = append(svcs, bacwrite.AllowedService{ServiceChoice: uint8(s)})
			}
			mut := bacwrite.SessionMutation(target, svcs)
			cmd.Printf("Protocol:     bacnet\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Services:     %s\n", canonUintList(serviceChoices))
			cmd.Printf("Always-safe:  unconfirmed-requests + acks + confirmed-reads + non-BACnet\n")
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileBACnet(target, serviceChoices))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the BACnet/IP device we'll proxy to)")
	cmd.Flags().UintSliceVar(&serviceChoices, "service-choice", nil, "confirmed-service choices to allow (15 WriteProperty, 20 ReinitializeDevice, etc.)")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
	return cmd
}

// ---- shared helpers for opcua + bacnet ------------------------

// parseNodeIDFlag parses `ns=N;i=M` into an opwrite.AllowedNodeID.
// Spaces around tokens are tolerated.
func parseNodeIDFlag(s string) (opwrite.AllowedNodeID, error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ";")
	if len(parts) != 2 {
		return opwrite.AllowedNodeID{}, fmt.Errorf("--node-id %q: want ns=N;i=M", s)
	}
	var ns uint64
	var id uint64
	for _, p := range parts {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return opwrite.AllowedNodeID{}, fmt.Errorf("--node-id %q: each token is KEY=VALUE", s)
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return opwrite.AllowedNodeID{}, fmt.Errorf("--node-id %q: %q is not a number", s, val)
		}
		switch strings.ToLower(key) {
		case "ns":
			if n > 0xFFFF {
				return opwrite.AllowedNodeID{}, fmt.Errorf("--node-id %q: ns must fit in uint16", s)
			}
			ns = n
		case "i":
			id = n
		default:
			return opwrite.AllowedNodeID{}, fmt.Errorf("--node-id %q: unknown key %q (expected ns or i)", s, key)
		}
	}
	// ns is guaranteed ≤ 0xFFFF by the range check above; id is
	// capped to 32 bits by ParseUint(..., 32).
	return opwrite.AllowedNodeID{
		Namespace:  uint16(ns & 0xFFFF),
		Identifier: uint32(id & 0xFFFFFFFF),
	}, nil
}

// canonUintList returns a sorted deduped decimal list for
// operator-readable output.
func canonUintList(in []uint) string {
	if len(in) == 0 {
		return "(none)"
	}
	set := map[uint]struct{}{}
	for _, v := range in {
		set[v] = struct{}{}
	}
	out := make([]uint, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	parts := make([]string, len(out))
	for i, v := range out {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, ", ")
}

// canonNodeIDs prints the sorted list in ns=N;i=M form.
func canonNodeIDs(in []opwrite.AllowedNodeID) string {
	if len(in) == 0 {
		return "(none — gate only at service-TypeID level)"
	}
	out := make([]string, len(in))
	sorted := append([]opwrite.AllowedNodeID(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Namespace != sorted[j].Namespace {
			return sorted[i].Namespace < sorted[j].Namespace
		}
		return sorted[i].Identifier < sorted[j].Identifier
	})
	for i, n := range sorted {
		out[i] = fmt.Sprintf("ns=%d;i=%d", n.Namespace, n.Identifier)
	}
	return strings.Join(out, ", ")
}

// buildAllowFileOPCUA builds the YAML for an OPC UA proxy
// session. v1.9 closes the v1.7 carry-over by persisting
// per-NodeId entries alongside the service-TypeID allowlist —
// the emitted YAML now round-trips cleanly through
// loadAllowFile.
func buildAllowFileOPCUA(target string, services []uint, nodeIDRaw []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin:   pluginNameOPCUA,
		Target:   target,
		Services: canonUints(services),
	}
	if len(nodeIDRaw) > 0 {
		af.NodeIDs = make([]proxyNodeID, 0, len(nodeIDRaw))
		for _, raw := range nodeIDRaw {
			nid, err := parseNodeIDFlag(raw)
			if err != nil {
				// Parse error surfaced upstream by the dry-run's
				// pre-check; if we got here the flag is valid.
				continue
			}
			af.NodeIDs = append(af.NodeIDs, proxyNodeID{
				Namespace:  nid.Namespace,
				Identifier: nid.Identifier,
			})
		}
		// Sort for determinism — loadAllowFile + hash functions
		// already sort, but the emitted file should be stable
		// across invocations too.
		sort.Slice(af.NodeIDs, func(i, j int) bool {
			if af.NodeIDs[i].Namespace != af.NodeIDs[j].Namespace {
				return af.NodeIDs[i].Namespace < af.NodeIDs[j].Namespace
			}
			return af.NodeIDs[i].Identifier < af.NodeIDs[j].Identifier
		})
	}
	return af
}

// buildAllowFileBACnet builds the YAML for a BACnet proxy session.
func buildAllowFileBACnet(target string, choices []uint) proxyAllowFile {
	return proxyAllowFile{
		Plugin:         pluginNameBACnet,
		Target:         target,
		ServiceChoices: canonUints(choices),
	}
}

// canonUints returns a sorted deduped copy of in.
func canonUints(in []uint) []uint {
	set := map[uint]struct{}{}
	for _, v := range in {
		set[v] = struct{}{}
	}
	out := make([]uint, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
