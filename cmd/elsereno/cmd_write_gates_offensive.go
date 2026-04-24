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
	cwmpwrite "local/elsereno/offensive/write/cwmp"
	iaxwrite "local/elsereno/offensive/write/iax2"
	opwrite "local/elsereno/offensive/write/opcua"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	sipwrite "local/elsereno/offensive/write/sip"

	"local/elsereno/internal/core"
)

// displayNone is the canonical empty-list placeholder for
// operator-facing dry-run output. Individual subcommands append
// a per-field explanation where helpful.
const displayNone = "(none)"

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
	var methods, toPrefixes, aors, fromDomains []string
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
			aorList := make([]sipwrite.AllowedAOR, 0, len(aors))
			for _, a := range aors {
				aorList = append(aorList, sipwrite.AllowedAOR{AOR: a})
			}
			fromDomainList := make([]sipwrite.AllowedFromDomain, 0, len(fromDomains))
			for _, d := range fromDomains {
				fromDomainList = append(fromDomainList, sipwrite.AllowedFromDomain{Domain: d})
			}
			mut := sipwrite.SessionMutationWithFromDomains(target, allowed, prefixes, aorList, fromDomainList)
			printSIPDryRunSummary(cmd, target, methods, toPrefixes, aors, fromDomains, mut)
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileSIP(target, methods, toPrefixes, aors, fromDomains))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the SIP server we'll proxy to)")
	cmd.Flags().StringSliceVar(&methods, "method", nil, "one or more gated methods (repeat or comma-separated)")
	cmd.Flags().StringSliceVar(&toPrefixes, "to-prefix", nil,
		"optional: INVITE destination allowlist — URI user-part prefixes (e.g. +34, +44). Only applies to INVITE; other methods unaffected. Toll-fraud mitigation (v1.9+).")
	cmd.Flags().StringSliceVar(&aors, "aor", nil,
		"optional: REGISTER AOR allowlist — exact AoRs (e.g. sip:alice@pbx.internal). Only applies to REGISTER; exact match, not prefix. Registration-hijack mitigation (v1.10+).")
	cmd.Flags().StringSliceVar(&fromDomains, "from-domain", nil,
		"optional: From-header domain allowlist — exact host match (e.g. internal.pbx). Applies to every gated method. Identity-spoof mitigation (v1.12+).")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
	return cmd
}

// printSIPDryRunSummary writes the human-readable block for the
// sip dry-run. Extracted so the RunE body stays under funlen.
func printSIPDryRunSummary(cmd *cobra.Command, target string, methods, toPrefixes, aors, fromDomains []string, mut confirm.Mutation) {
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
	if len(aors) > 0 {
		cmd.Printf("AORs:         %s\n", canonAORs(aors))
	} else {
		cmd.Printf("AORs:         (none — REGISTER AoR not constrained)\n")
	}
	if len(fromDomains) > 0 {
		cmd.Printf("FromDomains:  %s\n", canonFromDomains(fromDomains))
	} else {
		cmd.Printf("FromDomains:  (none — From: domain not constrained)\n")
	}
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
}

// canonFromDomains prints a sorted, dedup'd, lowercased list of
// From-domain inputs for dry-run output.
func canonFromDomains(in []string) string {
	if len(in) == 0 {
		return displayNone
	}
	cleaned := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, dup := seen[d]; dup {
			continue
		}
		seen[d] = struct{}{}
		cleaned = append(cleaned, d)
	}
	sort.Strings(cleaned)
	return strings.Join(cleaned, ", ")
}

// canonAORs prints a sorted comma-separated list of AoR inputs
// after canonicalising each (scheme stripped, lowercased host).
// Used only for the dry-run operator output — the hash function
// does its own canonicalisation independently.
func canonAORs(in []string) string {
	if len(in) == 0 {
		return displayNone
	}
	cleaned := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		cleaned = append(cleaned, a)
	}
	sort.Strings(cleaned)
	return strings.Join(cleaned, ", ")
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
Add --node-id (repeatable) to tighten the gate to specific
target NodeIds. Accepted NodeId forms:

  ns=N;i=M    numeric identifier (TwoByte / FourByte / Numeric)
  ns=N;s=STR  string identifier
  ns=N;g=HEX  Guid identifier (32 hex chars; dashes tolerated)
  ns=N;b=HEX  ByteString identifier

A WriteRequest then passes only when both its service TypeID is
allowed AND EVERY WriteValue's NodeId matches one of the
per-node allowlist entries (v1.12 walks the full NodesToWrite
batch; v1.6 chunk 2 only checked the first). Unparseable
WriteValue layouts / DataValue encodings are refused — the
gate fails closed.`,
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
			nids, canonNids, err := parseNodeIDFlags(nodeIDs)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			mut := opwrite.SessionMutationWithRichNodeIDs(target, svcs, nids, canonNids)
			cmd.Printf("Protocol:     opcua\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Services:     %s\n", canonUintList(services))
			cmd.Printf("NodeIDs:      %s\n", canonNodeIDsRich(nids, canonNids))
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
	cmd.Flags().StringSliceVar(&nodeIDs, "node-id", nil, "optional NodeId(s) to restrict WriteRequests to; accepts ns=N;i=M (numeric), ns=N;s=STR (string), ns=N;g=HEX (guid), ns=N;b=HEX (bytestring)")
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

// ---- elsereno write cwmp -------------------------------------

func newWriteCWMPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cwmp",
		Short: "TR-069 / CWMP ACS-CPE SOAP RPC-gated proxy (dry-run derives the session confirm-token)",
		Long: `The gated CWMP proxy forwards all non-POST requests
unconditionally, and POSTs whose SOAP Body's first child is a
read-only / protocol-flow RPC (GetParameter{Names,Values,
Attributes}, GetRPCMethods, Inform/InformResponse,
TransferComplete, Kicked, Fault). POSTs whose RPC is write-
capable (SetParameterValues, SetParameterAttributes, AddObject,
DeleteObject, Reboot, FactoryReset, Download, Upload,
ScheduleInform, ScheduleDownload, ChangeDUState, CancelTransfer)
require explicit --rpc allowlist entries.

Refusal emits a CWMP SOAP Fault (TR-069 Annex A FaultCode 9001
"Request denied") so ACS code parses the rejection as a proper
CWMP-layer error rather than a transport glitch.`,
	}
	cmd.AddCommand(newWriteCWMPDryRunCmd())
	return cmd
}

func newWriteCWMPDryRunCmd() *cobra.Command {
	var target, ppFile, emitFile string
	var rpcs, paramPrefixes []string
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" {
				return fail(core.ExitUsage, errors.New("--target is required"))
			}
			allowed := make([]cwmpwrite.AllowedRPC, 0, len(rpcs))
			for _, r := range rpcs {
				allowed = append(allowed, cwmpwrite.AllowedRPC{Name: r})
			}
			paths := make([]cwmpwrite.AllowedParameterPath, 0, len(paramPrefixes))
			for _, p := range paramPrefixes {
				paths = append(paths, cwmpwrite.AllowedParameterPath{Prefix: p})
			}
			mut := cwmpwrite.SessionMutationWithParameterPaths(target, allowed, paths)
			cmd.Printf("Protocol:     cwmp\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("RPCs:         %s\n", canonCWMPRPCs(rpcs))
			cmd.Printf("Always-safe:  GetParameter{Names,Values,Attributes}, GetRPCMethods, Inform{,Response}, TransferComplete, Kicked, Fault (+ non-POST)\n")
			if len(paramPrefixes) > 0 {
				cmd.Printf("ParamPaths:   %s\n", canonCWMPPaths(paramPrefixes))
			} else {
				cmd.Printf("ParamPaths:   (none — Set* RPCs can target any parameter path)\n")
			}
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileCWMP(target, rpcs, paramPrefixes))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the CWMP ACS we'll proxy to)")
	cmd.Flags().StringSliceVar(&rpcs, "rpc", nil, "SOAP RPC name(s) to allow — case-sensitive per TR-069 §A.4 (e.g. SetParameterValues, Reboot, FactoryReset). Copy-paste from wire captures with \"cwmp:\" prefix is tolerated.")
	cmd.Flags().StringSliceVar(&paramPrefixes, "param-prefix", nil, "optional: per-parameter-path allowlist — prefixes like \"InternetGatewayDevice.WANDevice.\" constrain Set* RPCs to specific sub-trees. Only applies to SetParameterValues / SetParameterAttributes; other RPCs unaffected. Case-sensitive. Registration-hijack / partition mitigation (v1.12+).")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
	return cmd
}

// canonCWMPPaths produces an operator-friendly sorted dedup'd
// display of parameter-path prefixes. Case preserved.
func canonCWMPPaths(in []string) string {
	if len(in) == 0 {
		return displayNone
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// canonCWMPRPCs returns a sorted, deduped, prefix-stripped
// comma-separated list of RPC names for operator-friendly
// display. Case is preserved (CWMP RPC names are case-
// sensitive).
func canonCWMPRPCs(in []string) string {
	if len(in) == 0 {
		return "(none — all write-capable RPCs refused; reads still pass)"
	}
	set := map[string]struct{}{}
	for _, r := range in {
		r = strings.TrimSpace(r)
		if i := strings.IndexByte(r, ':'); i > 0 {
			r = r[i+1:]
		}
		r = strings.TrimSpace(r)
		if r != "" {
			set[r] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// ---- shared helpers for opcua + bacnet ------------------------

// parsedNodeIDFlag is the tagged union produced by
// parseNodeIDFlag. Exactly one of Numeric / Canonical is
// populated. Numeric is the v1.6 fast path (ns + uint32 id);
// Canonical is the v1.12 chunk-3 path that carries any of the
// s= / g= / b= encodings in canonical-string form.
type parsedNodeIDFlag struct {
	Numeric   *opwrite.AllowedNodeID
	Canonical opwrite.AllowedCanonicalNodeID
}

// parseNodeIDFlag parses one `--node-id` value into its
// numeric-or-canonical form. Accepted input shapes:
//
//	ns=N;i=M   → numeric (ns uint16, id uint32)
//	ns=N;s=STR → canonical string NodeID
//	ns=N;g=HEX → canonical GUID NodeID (32 hex chars, dashes
//	             tolerated, normalised to uppercase)
//	ns=N;b=HEX → canonical ByteString NodeID (any even hex,
//	             normalised to uppercase)
//
// Spaces around tokens are tolerated. ns must fit in uint16.
func parseNodeIDFlag(s string) (parsedNodeIDFlag, error) {
	ns, idKey, idVal, err := splitNodeIDTokens(s)
	if err != nil {
		return parsedNodeIDFlag{}, err
	}
	return buildParsedNodeID(s, ns, idKey, idVal)
}

// splitNodeIDTokens validates the `KEY=VALUE;KEY=VALUE` shape
// and extracts the (ns, idKey, idVal) triple.
func splitNodeIDTokens(s string) (ns uint16, idKey, idVal string, err error) {
	raw := strings.TrimSpace(s)
	parts := strings.Split(raw, ";")
	if len(parts) != 2 {
		return 0, "", "", fmt.Errorf("--node-id %q: want ns=N;i=M|s=STR|g=HEX|b=HEX", s)
	}
	var nsSeen bool
	for _, p := range parts {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return 0, "", "", fmt.Errorf("--node-id %q: each token is KEY=VALUE", s)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "ns":
			n, parseErr := strconv.ParseUint(val, 10, 32)
			if parseErr != nil {
				return 0, "", "", fmt.Errorf("--node-id %q: ns %q is not a number", s, val)
			}
			if n > 0xFFFF {
				return 0, "", "", fmt.Errorf("--node-id %q: ns must fit in uint16", s)
			}
			ns = uint16(n & 0xFFFF)
			nsSeen = true
		case "i", "s", "g", "b":
			idKey = key
			idVal = val
		default:
			return 0, "", "", fmt.Errorf("--node-id %q: unknown key %q (expected ns, i, s, g, or b)", s, key)
		}
	}
	if !nsSeen || idKey == "" {
		return 0, "", "", fmt.Errorf("--node-id %q: must specify both ns= and one of i/s/g/b", s)
	}
	return ns, idKey, idVal, nil
}

// buildParsedNodeID finalises the parsedNodeIDFlag from the
// split tokens. Per-kind validation + normalisation lives here.
func buildParsedNodeID(orig string, ns uint16, idKey, idVal string) (parsedNodeIDFlag, error) {
	switch idKey {
	case "i":
		n, err := strconv.ParseUint(idVal, 10, 32)
		if err != nil {
			return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: i %q is not a number", orig, idVal)
		}
		id := uint32(n & 0xFFFFFFFF)
		return parsedNodeIDFlag{
			Numeric: &opwrite.AllowedNodeID{Namespace: ns, Identifier: id},
		}, nil
	case "s":
		if idVal == "" {
			return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: s= must not be empty", orig)
		}
		return parsedNodeIDFlag{
			Canonical: opwrite.AllowedCanonicalNodeID(fmt.Sprintf("ns=%d;s=%s", ns, idVal)),
		}, nil
	case "g":
		hex, err := normaliseHex(idVal)
		if err != nil {
			return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: g %q: %w", orig, idVal, err)
		}
		if len(hex) != 32 {
			return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: g= must be 32 hex chars (16 bytes), got %d", orig, len(hex))
		}
		return parsedNodeIDFlag{
			Canonical: opwrite.AllowedCanonicalNodeID(fmt.Sprintf("ns=%d;g=%s", ns, hex)),
		}, nil
	case "b":
		hex, err := normaliseHex(idVal)
		if err != nil {
			return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: b %q: %w", orig, idVal, err)
		}
		if len(hex) == 0 {
			return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: b= must not be empty", orig)
		}
		return parsedNodeIDFlag{
			Canonical: opwrite.AllowedCanonicalNodeID(fmt.Sprintf("ns=%d;b=%s", ns, hex)),
		}, nil
	}
	return parsedNodeIDFlag{}, fmt.Errorf("--node-id %q: internal parser error", orig)
}

// normaliseHex strips dashes, validates hex, and uppercases.
// Returns the canonical uppercase form.
func normaliseHex(s string) (string, error) {
	s = strings.ReplaceAll(s, "-", "")
	if len(s)%2 != 0 {
		return "", fmt.Errorf("odd number of hex chars (%d)", len(s))
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			out[i] = c
		case c >= 'A' && c <= 'F':
			out[i] = c
		case c >= 'a' && c <= 'f':
			out[i] = c - ('a' - 'A')
		default:
			return "", fmt.Errorf("non-hex char %q", c)
		}
	}
	return string(out), nil
}

// canonUintList returns a sorted deduped decimal list for
// operator-readable output.
func canonUintList(in []uint) string {
	if len(in) == 0 {
		return displayNone
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

// parseNodeIDFlags splits a []string of --node-id values into
// the numeric + canonical lists expected by
// SessionMutationWithRichNodeIDs.
func parseNodeIDFlags(in []string) ([]opwrite.AllowedNodeID, []opwrite.AllowedCanonicalNodeID, error) {
	nids := make([]opwrite.AllowedNodeID, 0, len(in))
	canonNids := make([]opwrite.AllowedCanonicalNodeID, 0, len(in))
	for _, n := range in {
		parsed, err := parseNodeIDFlag(n)
		if err != nil {
			return nil, nil, err
		}
		if parsed.Numeric != nil {
			nids = append(nids, *parsed.Numeric)
		} else {
			canonNids = append(canonNids, parsed.Canonical)
		}
	}
	return nids, canonNids, nil
}

// canonNodeIDsRich prints the sorted combined list (numeric +
// canonical) in canonical string form.
func canonNodeIDsRich(nids []opwrite.AllowedNodeID, canonNids []opwrite.AllowedCanonicalNodeID) string {
	if len(nids) == 0 && len(canonNids) == 0 {
		return "(none — gate only at service-TypeID level)"
	}
	out := make([]string, 0, len(nids)+len(canonNids))
	sortedNids := append([]opwrite.AllowedNodeID(nil), nids...)
	sort.Slice(sortedNids, func(i, j int) bool {
		if sortedNids[i].Namespace != sortedNids[j].Namespace {
			return sortedNids[i].Namespace < sortedNids[j].Namespace
		}
		return sortedNids[i].Identifier < sortedNids[j].Identifier
	})
	for _, n := range sortedNids {
		out = append(out, fmt.Sprintf("ns=%d;i=%d", n.Namespace, n.Identifier))
	}
	sortedCanon := append([]opwrite.AllowedCanonicalNodeID(nil), canonNids...)
	sort.Slice(sortedCanon, func(i, j int) bool { return sortedCanon[i] < sortedCanon[j] })
	for _, c := range sortedCanon {
		out = append(out, string(c))
	}
	return strings.Join(out, ", ")
}

// buildAllowFileOPCUA builds the YAML for an OPC UA proxy
// session. v1.9 closes the v1.7 carry-over by persisting
// per-NodeId entries alongside the service-TypeID allowlist —
// the emitted YAML now round-trips cleanly through
// loadAllowFile. v1.12 chunk 3 extends node_ids with s= / g= /
// b= canonical-form entries (see proxyNodeID for schema).
func buildAllowFileOPCUA(target string, services []uint, nodeIDRaw []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin:   pluginNameOPCUA,
		Target:   target,
		Services: canonUints(services),
	}
	if len(nodeIDRaw) == 0 {
		return af
	}
	af.NodeIDs = make([]proxyNodeID, 0, len(nodeIDRaw))
	for _, raw := range nodeIDRaw {
		parsed, err := parseNodeIDFlag(raw)
		if err != nil {
			// Parse error surfaced upstream by the dry-run's
			// pre-check; if we got here the flag is valid.
			continue
		}
		if parsed.Numeric != nil {
			af.NodeIDs = append(af.NodeIDs, proxyNodeID{
				Namespace:  parsed.Numeric.Namespace,
				Identifier: parsed.Numeric.Identifier,
			})
			continue
		}
		// Canonical entry: stash as the single Canonical field.
		af.NodeIDs = append(af.NodeIDs, proxyNodeID{
			Canonical: string(parsed.Canonical),
		})
	}
	// Sort for determinism — loadAllowFile + hash functions
	// already sort, but the emitted file should be stable
	// across invocations too.
	sort.Slice(af.NodeIDs, func(i, j int) bool {
		// Numeric entries (Canonical == "") before canonical-
		// string entries; within numeric, by (ns, id); within
		// canonical, by canonical string.
		if af.NodeIDs[i].Canonical == "" && af.NodeIDs[j].Canonical != "" {
			return true
		}
		if af.NodeIDs[i].Canonical != "" && af.NodeIDs[j].Canonical == "" {
			return false
		}
		if af.NodeIDs[i].Canonical == "" {
			// both numeric
			if af.NodeIDs[i].Namespace != af.NodeIDs[j].Namespace {
				return af.NodeIDs[i].Namespace < af.NodeIDs[j].Namespace
			}
			return af.NodeIDs[i].Identifier < af.NodeIDs[j].Identifier
		}
		return af.NodeIDs[i].Canonical < af.NodeIDs[j].Canonical
	})
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
