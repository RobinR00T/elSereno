//go:build offensive

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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
	var callMethods []string
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
			calls, err := parseCallMethodFlags(callMethods)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			mut := opwrite.SessionMutationWithCallMethods(target, svcs, nids, canonNids, calls)
			cmd.Printf("Protocol:     opcua\n")
			cmd.Printf("Operation:    proxy_session\n")
			cmd.Printf("Target:       %s\n", target)
			cmd.Printf("Services:     %s\n", canonUintList(services))
			cmd.Printf("NodeIDs:      %s\n", canonNodeIDsRich(nids, canonNids))
			cmd.Printf("CallMethods:  %s\n", canonCallMethods(calls))
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileOPCUA(target, services, nodeIDs, callMethods))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the OPC UA server we'll proxy to)")
	cmd.Flags().UintSliceVar(&services, "service", nil, "service TypeID(s) to allow (e.g. 673 WriteRequest, 704 CallRequest)")
	cmd.Flags().StringSliceVar(&nodeIDs, "node-id", nil, "optional NodeId(s) to restrict WriteRequests to; accepts ns=N;i=M (numeric), ns=N;s=STR (string), ns=N;g=HEX (guid), ns=N;b=HEX (bytestring)")
	cmd.Flags().StringSliceVar(&callMethods, "call-method", nil, "optional: per-CallMethod allowlist. Format: object=<NodeId>;method=<NodeId>  where each <NodeId> is a canonical-string form (ns=N;i=M | s=STR | g=HEX | b=HEX). Repeatable; exact match only. v1.12+.")
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
	var objects []string
	var deleteObjects []string
	var createObjectTypes, reinitStates []uint
	cmd := &cobra.Command{
		Use:   "dry-run",
		Short: "Print session PayloadHash + allowlist (optional --vault-passphrase-file mints the confirm-token)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBACnetDryRun(cmd, bacnetDryRunInputs{
				target:            target,
				ppFile:            ppFile,
				emitFile:          emitFile,
				serviceChoices:    serviceChoices,
				objects:           objects,
				deleteObjects:     deleteObjects,
				createObjectTypes: createObjectTypes,
				reinitStates:      reinitStates,
			})
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the BACnet/IP device we'll proxy to)")
	cmd.Flags().UintSliceVar(&serviceChoices, "service-choice", nil, "confirmed-service choices to allow (15 WriteProperty, 20 ReinitializeDevice, etc.)")
	cmd.Flags().StringSliceVar(&objects, "object", nil, "optional: per-object allowlist for WriteProperty (svc 15) and WritePropertyMultiple (svc 16). Format: type=N;instance=M;property=P (repeatable, exact match). v1.12+ (svc 15) and v1.13+ (svc 16).")
	cmd.Flags().StringSliceVar(&deleteObjects, "delete-object", nil, "optional: per-target allowlist for DeleteObject (svc 11). Format: type=N;instance=M (repeatable, exact match). Object-level only — no PropertyID dimension. v1.13+.")
	cmd.Flags().UintSliceVar(&createObjectTypes, "create-object-type", nil, "optional: per-type allowlist for CreateObject (svc 10). Numeric BACnetObjectType (e.g. 17 for Schedule). Type-only — instance ignored at gate level. v1.13+.")
	cmd.Flags().UintSliceVar(&reinitStates, "reinit-state", nil, "optional: per-state allowlist for ReinitializeDevice (svc 20). Numeric reinitializedStateOfDevice enum (0 coldstart, 1 warmstart, 2..6 backup/restore, 7 activate-changes). Operator typically allows only 7. v1.13+.")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
	return cmd
}

// bacnetDryRunInputs bundles the dry-run flags into a single
// arg so runBACnetDryRun stays under the gocyclo / funlen
// thresholds as we add v1.13+ per-service dimensions.
type bacnetDryRunInputs struct {
	target, ppFile, emitFile        string
	serviceChoices                  []uint
	objects                         []string
	deleteObjects                   []string
	createObjectTypes, reinitStates []uint
}

// runBACnetDryRun parses every per-service allowlist, computes
// the session PayloadHash, prints the operator-facing summary,
// optionally mints the confirm-token + emits the YAML.
func runBACnetDryRun(cmd *cobra.Command, in bacnetDryRunInputs) error {
	if in.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	svcs, err := parseBACnetServiceChoices(in.serviceChoices)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	objs, err := parseBACnetObjectFlags(in.objects)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	delObjs, err := parseBACnetDeleteObjectFlags(in.deleteObjects)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	creObjs, err := parseBACnetCreateObjectTypes(in.createObjectTypes)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	reiSts, err := parseBACnetReinitStates(in.reinitStates)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	mut := bacwrite.SessionMutationWithReinitStates(in.target, svcs, objs, delObjs, creObjs, reiSts)
	printBACnetDryRunSummary(cmd, in, svcs, objs, delObjs, creObjs, reiSts, mut)
	if err := maybeMintToken(cmd, mut, in.ppFile); err != nil {
		return err
	}
	if p, err := ensureAllowFilePath(in.emitFile); err == nil {
		return emitAllowFile(cmd, p, buildAllowFileBACnet(in.target, in.serviceChoices, in.objects, in.deleteObjects, in.createObjectTypes, in.reinitStates))
	}
	return nil
}

// parseBACnetServiceChoices validates uint values fit in 1 byte.
func parseBACnetServiceChoices(in []uint) ([]bacwrite.AllowedService, error) {
	out := make([]bacwrite.AllowedService, 0, len(in))
	for _, s := range in {
		if s > 0xFF {
			return nil, fmt.Errorf("--service-choice %d: must be 0-255", s)
		}
		out = append(out, bacwrite.AllowedService{ServiceChoice: uint8(s)})
	}
	return out, nil
}

// printBACnetDryRunSummary emits the canonical dry-run output.
func printBACnetDryRunSummary(cmd *cobra.Command, in bacnetDryRunInputs, svcs []bacwrite.AllowedService, objs []bacwrite.AllowedObject, delObjs []bacwrite.AllowedDeleteObject, creObjs []bacwrite.AllowedCreateObject, reiSts []bacwrite.AllowedReinitState, mut confirm.Mutation) {
	_ = svcs // service list canonicalised via in.serviceChoices.
	cmd.Printf("Protocol:     bacnet\n")
	cmd.Printf("Operation:    proxy_session\n")
	cmd.Printf("Target:       %s\n", in.target)
	cmd.Printf("Services:     %s\n", canonUintList(in.serviceChoices))
	cmd.Printf("Objects:      %s\n", canonBACnetObjects(objs))
	cmd.Printf("DeleteObjects: %s\n", canonBACnetDeleteObjects(delObjs))
	cmd.Printf("CreateObjects: %s\n", canonBACnetCreateObjects(creObjs))
	cmd.Printf("ReinitStates: %s\n", canonBACnetReinitStates(reiSts))
	cmd.Printf("Always-safe:  unconfirmed-requests + acks + confirmed-reads + non-BACnet\n")
	cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
}

// parseBACnetObjectFlags parses --object entries into
// AllowedObject{Type, Instance, Property} tuples.
func parseBACnetObjectFlags(in []string) ([]bacwrite.AllowedObject, error) {
	out := make([]bacwrite.AllowedObject, 0, len(in))
	for _, raw := range in {
		o, err := parseBACnetObjectFlag(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// parseBACnetObjectFlag parses one --object value.
// Format: type=N;instance=M;property=P. Spaces tolerated.
func parseBACnetObjectFlag(s string) (bacwrite.AllowedObject, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: empty", s)
	}
	var out bacwrite.AllowedObject
	var typeSeen, instSeen, propSeen bool
	for _, p := range strings.Split(raw, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: each token is KEY=VALUE", s)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: %s %q is not a number", s, key, val)
		}
		switch key {
		case "type":
			if n > 0x3FF {
				return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: type must be 0-1023 (10 bits)", s)
			}
			out.ObjectType = uint16(n & 0x3FF)
			typeSeen = true
		case "instance":
			if n > 0x3FFFFF {
				return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: instance must be 0-4194303 (22 bits)", s)
			}
			out.ObjectInstance = uint32(n & 0x3FFFFF)
			instSeen = true
		case "property":
			out.PropertyID = uint32(n & 0xFFFFFFFF)
			propSeen = true
		default:
			return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: unknown key %q (expected type, instance, or property)", s, key)
		}
	}
	if !typeSeen || !instSeen || !propSeen {
		return bacwrite.AllowedObject{}, fmt.Errorf("--object %q: must specify type=, instance=, and property=", s)
	}
	return out, nil
}

// parseBACnetDeleteObjectFlags parses --delete-object entries
// into AllowedDeleteObject{Type, Instance} tuples.
func parseBACnetDeleteObjectFlags(in []string) ([]bacwrite.AllowedDeleteObject, error) {
	out := make([]bacwrite.AllowedDeleteObject, 0, len(in))
	for _, raw := range in {
		o, err := parseBACnetDeleteObjectFlag(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// parseBACnetDeleteObjectFlag parses one --delete-object value.
// Format: type=N;instance=M. Same shape as --object minus the
// property field.
func parseBACnetDeleteObjectFlag(s string) (bacwrite.AllowedDeleteObject, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: empty", s)
	}
	var out bacwrite.AllowedDeleteObject
	var typeSeen, instSeen bool
	for _, p := range strings.Split(raw, ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: each token is KEY=VALUE", s)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		n, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: %s %q is not a number", s, key, val)
		}
		switch key {
		case "type":
			if n > 0x3FF {
				return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: type must be 0-1023 (10 bits)", s)
			}
			out.ObjectType = uint16(n & 0x3FF)
			typeSeen = true
		case "instance":
			if n > 0x3FFFFF {
				return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: instance must be 0-4194303 (22 bits)", s)
			}
			out.ObjectInstance = uint32(n & 0x3FFFFF)
			instSeen = true
		default:
			return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: unknown key %q (expected type or instance)", s, key)
		}
	}
	if !typeSeen || !instSeen {
		return bacwrite.AllowedDeleteObject{}, fmt.Errorf("--delete-object %q: must specify both type= and instance=", s)
	}
	return out, nil
}

// parseBACnetCreateObjectTypes converts repeated --create-object-type
// uint values into AllowedCreateObject{Type} entries. Each value
// must fit in 10 bits (BACnetObjectType range).
func parseBACnetCreateObjectTypes(in []uint) ([]bacwrite.AllowedCreateObject, error) {
	out := make([]bacwrite.AllowedCreateObject, 0, len(in))
	for _, v := range in {
		if v > 0x3FF {
			return nil, fmt.Errorf("--create-object-type %d: must be 0-1023 (10 bits)", v)
		}
		out = append(out, bacwrite.AllowedCreateObject{ObjectType: uint16(v & 0x3FF)})
	}
	return out, nil
}

// parseBACnetReinitStates converts repeated --reinit-state uint
// values into AllowedReinitState entries. Each value must be a
// known enum (0..7 per ASHRAE 135 §16.4).
func parseBACnetReinitStates(in []uint) ([]bacwrite.AllowedReinitState, error) {
	out := make([]bacwrite.AllowedReinitState, 0, len(in))
	for _, v := range in {
		if v > 7 {
			return nil, fmt.Errorf("--reinit-state %d: must be 0-7 (ASHRAE 135 §16.4 enum)", v)
		}
		out = append(out, bacwrite.AllowedReinitState{State: uint8(v & 0x07)})
	}
	return out, nil
}

// canonBACnetReinitStates prints the sorted list for dry-run,
// labelling each known state for operator readability.
func canonBACnetReinitStates(in []bacwrite.AllowedReinitState) string {
	if len(in) == 0 {
		return "(none — ReinitializeDevice accepts any state when 20 is in services)"
	}
	out := make([]string, len(in))
	sorted := append([]bacwrite.AllowedReinitState(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].State < sorted[j].State })
	for i, r := range sorted {
		out[i] = fmt.Sprintf("%d (%s)", r.State, reinitStateLabel(r.State))
	}
	return strings.Join(out, ", ")
}

// reinitStateLabel returns the spec name for an enum value.
// Unknown values render as "?" — never expected since the
// parser validates the range.
func reinitStateLabel(v uint8) string {
	switch v {
	case 0:
		return "coldstart"
	case 1:
		return "warmstart"
	case 2:
		return "startbackup"
	case 3:
		return "endbackup"
	case 4:
		return "startrestore"
	case 5:
		return "endrestore"
	case 6:
		return "abortrestore"
	case 7:
		return "activate-changes"
	default:
		return "?"
	}
}

// canonBACnetCreateObjects prints the sorted list for dry-run.
func canonBACnetCreateObjects(in []bacwrite.AllowedCreateObject) string {
	if len(in) == 0 {
		return "(none — CreateObject accepts any object-type when 10 is in services)"
	}
	out := make([]string, len(in))
	sorted := append([]bacwrite.AllowedCreateObject(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ObjectType < sorted[j].ObjectType })
	for i, c := range sorted {
		out[i] = fmt.Sprintf("type=%d", c.ObjectType)
	}
	return strings.Join(out, ", ")
}

// canonBACnetDeleteObjects prints the sorted list for dry-run.
func canonBACnetDeleteObjects(in []bacwrite.AllowedDeleteObject) string {
	if len(in) == 0 {
		return "(none — DeleteObject accepts any target when 11 is in services)"
	}
	out := make([]string, len(in))
	sorted := append([]bacwrite.AllowedDeleteObject(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ObjectType != sorted[j].ObjectType {
			return sorted[i].ObjectType < sorted[j].ObjectType
		}
		return sorted[i].ObjectInstance < sorted[j].ObjectInstance
	})
	for i, d := range sorted {
		out[i] = fmt.Sprintf("type=%d;instance=%d", d.ObjectType, d.ObjectInstance)
	}
	return strings.Join(out, ", ")
}

// canonBACnetObjects prints the sorted list for dry-run output.
func canonBACnetObjects(in []bacwrite.AllowedObject) string {
	if len(in) == 0 {
		return "(none — WriteProperty accepts any object when 15 is in services)"
	}
	out := make([]string, len(in))
	sorted := append([]bacwrite.AllowedObject(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ObjectType != sorted[j].ObjectType {
			return sorted[i].ObjectType < sorted[j].ObjectType
		}
		if sorted[i].ObjectInstance != sorted[j].ObjectInstance {
			return sorted[i].ObjectInstance < sorted[j].ObjectInstance
		}
		return sorted[i].PropertyID < sorted[j].PropertyID
	})
	for i, o := range sorted {
		out[i] = fmt.Sprintf("type=%d;instance=%d;property=%d", o.ObjectType, o.ObjectInstance, o.PropertyID)
	}
	return strings.Join(out, ", ")
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
	cmd.AddCommand(newWriteCWMPVerifyFirmwareCmd())
	return cmd
}

// newWriteCWMPVerifyFirmwareCmd is the v1.13 operator pre-flight
// verifier for the CWMP Download firmware-URL allowlist. Given
// an allow-file with `firmware:` entries, it side-fetches each
// URL via HTTP/HTTPS, computes SHA-256 over the response body,
// and compares against the operator-supplied SHA256 metadata.
//
// This catches firmware-swap attacks BEFORE the change window
// opens: an ACS that previously published a benign image at
// the URL might rotate to a malicious image right before the
// CPE fetches it. The CWMP gate (v1.12 chunk 10) only enforces
// URL match at RPC time; the actual hash isn't carried by
// TR-069 Download. This tool closes that loop pre-emptively.
//
// Exit codes: 0 all-match, 1 any-mismatch, 2 usage / fetch
// error.
func newWriteCWMPVerifyFirmwareCmd() *cobra.Command {
	var allowFile string
	var fetchTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "verify-firmware",
		Short: "Pre-flight: side-fetch each firmware URL and verify its SHA-256 against the allow-file",
		Long: `Reads the firmware: section of an allow-file YAML, downloads each
URL, computes SHA-256, and compares against the expected hash.

Use this BEFORE opening a change window: the CWMP gate (v1.12
chunk 10) enforces URL match at RPC time, but TR-069 Download
doesn't carry the firmware hash, so a hostile ACS could swap
the image at the URL between dry-run and real run. This tool
verifies the URL contents match operator expectation right now.

Entries without a sha256 field are skipped with a warning.

Exit code: 0 all match, 1 any mismatch, 2 usage / fetch error.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if allowFile == "" {
				return fail(core.ExitUsage, errors.New("--allow-file is required"))
			}
			af, err := loadCWMPFirmwareAllowFile(allowFile)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			if len(af.Firmware) == 0 {
				cmd.Printf("no firmware: entries in %s — nothing to verify\n", allowFile)
				return nil
			}
			results, anyFail := verifyCWMPFirmwareURLs(cmd.Context(), af.Firmware, fetchTimeout)
			printCWMPFirmwareVerifyResults(cmd, results)
			if anyFail {
				return fail(core.ExitError, errors.New("at least one firmware URL failed SHA-256 verification"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&allowFile, "allow-file", "", "path to the YAML allow-file with `firmware:` entries (required)")
	cmd.Flags().DurationVar(&fetchTimeout, "fetch-timeout", 60*time.Second, "per-URL fetch timeout (firmware images can be tens of MB)")
	return cmd
}

func newWriteCWMPDryRunCmd() *cobra.Command {
	var target, ppFile, emitFile string
	var rpcs, paramPrefixes, firmware []string
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
			fws, err := parseCWMPFirmwareFlags(firmware)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			mut := cwmpwrite.SessionMutationWithFirmware(target, allowed, paths, fws)
			// v1.13 chunk 4: warn when an --rpc value differs from
			// the canonical TR-069 §A.4 spelling only by case. The
			// gate is case-sensitive (per TR-069 §A.4), so a
			// lowercase entry would silently fail to match the
			// wire-side RPC. Surface this BEFORE the operator runs
			// the proxy with a token whose hash bakes in the wrong
			// case.
			emitCWMPRPCCaseWarnings(cmd, rpcs)
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
			cmd.Printf("Firmware:     %s\n", canonCWMPFirmware(fws))
			cmd.Printf("PayloadHash:  %s\n", hex.EncodeToString(mut.PayloadHash[:]))
			if err := maybeMintToken(cmd, mut, ppFile); err != nil {
				return err
			}
			if p, err := ensureAllowFilePath(emitFile); err == nil {
				return emitAllowFile(cmd, p, buildAllowFileCWMP(target, rpcs, paramPrefixes, firmware))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "upstream host:port (the CWMP ACS we'll proxy to)")
	cmd.Flags().StringSliceVar(&rpcs, "rpc", nil, "SOAP RPC name(s) to allow — case-sensitive per TR-069 §A.4 (e.g. SetParameterValues, Reboot, FactoryReset). Copy-paste from wire captures with \"cwmp:\" prefix is tolerated.")
	cmd.Flags().StringSliceVar(&paramPrefixes, "param-prefix", nil, "optional: per-parameter-path allowlist — prefixes like \"InternetGatewayDevice.WANDevice.\" constrain Set* RPCs to specific sub-trees. Only applies to SetParameterValues / SetParameterAttributes; other RPCs unaffected. Case-sensitive. Registration-hijack / partition mitigation (v1.12+).")
	cmd.Flags().StringSliceVar(&firmware, "firmware", nil, "optional: per-image allowlist for Download RPC. Format: url=<full-url>;sha256=<hex> (sha256 optional, repeatable). URL must EXACTLY match the <URL> the ACS sends; SHA256 is metadata for downstream verification (not enforced at RPC time — TR-069 doesn't carry it). v1.12+.")
	addPassphraseFileFlag(cmd, &ppFile)
	addEmitAllowFileFlag(cmd, &emitFile)
	return cmd
}

// parseCWMPFirmwareFlags parses --firmware values
// (`url=<u>;sha256=<hex>`). sha256= is optional.
func parseCWMPFirmwareFlags(in []string) ([]cwmpwrite.AllowedFirmware, error) {
	out := make([]cwmpwrite.AllowedFirmware, 0, len(in))
	for _, raw := range in {
		f, err := parseCWMPFirmwareFlag(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// parseCWMPFirmwareFlag parses one --firmware value. Splits on
// `;sha256=` so the embedded `;` inside URL query strings
// (e.g. `?id=1;tag=foo`) doesn't confuse the parser.
func parseCWMPFirmwareFlag(s string) (cwmpwrite.AllowedFirmware, error) {
	raw := strings.TrimSpace(s)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "url=") {
		return cwmpwrite.AllowedFirmware{}, fmt.Errorf("--firmware %q: must start with url=", s)
	}
	rest := raw[len("url="):]
	url := rest
	sha := ""
	idx := strings.Index(strings.ToLower(rest), ";sha256=")
	if idx >= 0 {
		url = strings.TrimSpace(rest[:idx])
		sha = strings.ToLower(strings.TrimSpace(rest[idx+len(";sha256="):]))
		if !validHexSHA256(sha) {
			return cwmpwrite.AllowedFirmware{}, fmt.Errorf("--firmware %q: sha256 must be 64 lowercase hex chars", s)
		}
	}
	if url == "" {
		return cwmpwrite.AllowedFirmware{}, fmt.Errorf("--firmware %q: url= must not be empty", s)
	}
	return cwmpwrite.AllowedFirmware{URL: url, SHA256: sha}, nil
}

// validHexSHA256 reports whether s is exactly 64 hex chars.
func validHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// firmwareVerifyStatus values as named constants — printed in
// the verify-firmware output and inspected by tests.
const (
	firmwareStatusMatch    = "match"
	firmwareStatusMismatch = "mismatch"
	firmwareStatusSkipped  = "skipped"
	firmwareStatusError    = "error"
)

// firmwareVerifyResult is one entry in the verify-firmware
// output: per-URL pass/fail with the diagnostic message.
type firmwareVerifyResult struct {
	URL          string
	ExpectedHash string
	GotHash      string
	Status       string // one of firmwareStatus* above
	Detail       string
}

// loadCWMPFirmwareAllowFile reads an allow-file YAML and
// returns the cwmp-relevant fields. Lighter than the proxy-
// listen loadAllowFile because verify-firmware doesn't need
// the rest of the YAML (RPCs, paths, etc.).
func loadCWMPFirmwareAllowFile(path string) (proxyAllowFile, error) {
	var opts proxyListenOpts
	if err := loadAllowFile(path, &opts); err != nil {
		return proxyAllowFile{}, err
	}
	// loadAllowFile populates opts.cwmpFirmware (CLI string form)
	// but discards the structured data; reload directly to get
	// the structured Firmware field.
	raw, err := os.ReadFile(path) // #nosec G304 — operator-supplied YAML path
	if err != nil {
		return proxyAllowFile{}, fmt.Errorf("--allow-file %s: %w", path, err)
	}
	var af proxyAllowFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&af); err != nil {
		return proxyAllowFile{}, fmt.Errorf("--allow-file %s: parse: %w", path, err)
	}
	return af, nil
}

// verifyCWMPFirmwareURLs side-fetches each entry and verifies
// SHA-256. Returns per-entry results + whether any entry failed
// (mismatch or fetch error).
func verifyCWMPFirmwareURLs(ctx context.Context, entries []proxyCWMPFirmware, timeout time.Duration) ([]firmwareVerifyResult, bool) {
	client := &http.Client{Timeout: timeout}
	results := make([]firmwareVerifyResult, 0, len(entries))
	anyFail := false
	for _, e := range entries {
		r := firmwareVerifyResult{URL: e.URL, ExpectedHash: e.SHA256}
		if e.SHA256 == "" {
			r.Status = firmwareStatusSkipped
			r.Detail = "no sha256 field; URL not verified"
			results = append(results, r)
			continue
		}
		got, err := fetchFirmwareSHA256(ctx, client, e.URL)
		switch {
		case err != nil:
			r.Status = firmwareStatusError
			r.Detail = err.Error()
			anyFail = true
		case strings.EqualFold(got, e.SHA256):
			r.Status = firmwareStatusMatch
			r.GotHash = got
		default:
			r.Status = firmwareStatusMismatch
			r.GotHash = got
			r.Detail = fmt.Sprintf("expected %s, got %s", e.SHA256, got)
			anyFail = true
		}
		results = append(results, r)
	}
	return results, anyFail
}

// fetchFirmwareSHA256 downloads url and returns the lowercase
// hex SHA-256 of the body. Bounded by client.Timeout. Body is
// streamed (no full-image buffering) — firmware can be tens of
// MB.
func fetchFirmwareSHA256(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// printCWMPFirmwareVerifyResults writes a per-URL line to the
// command's stdout. Uses cmd.Printf so callers can capture
// output in tests.
func printCWMPFirmwareVerifyResults(cmd *cobra.Command, results []firmwareVerifyResult) {
	cmd.Printf("Firmware verification (%d entries):\n", len(results))
	for _, r := range results {
		switch r.Status {
		case firmwareStatusMatch:
			cmd.Printf("  ✓ MATCH    %s\n", r.URL)
		case firmwareStatusMismatch:
			cmd.Printf("  ✗ MISMATCH %s\n             %s\n", r.URL, r.Detail)
		case firmwareStatusError:
			cmd.Printf("  ! ERROR    %s\n             %s\n", r.URL, r.Detail)
		case firmwareStatusSkipped:
			cmd.Printf("  - SKIPPED  %s (%s)\n", r.URL, r.Detail)
		}
	}
}

// canonCWMPFirmware prints the sorted list of firmware entries
// for operator dry-run output.
func canonCWMPFirmware(in []cwmpwrite.AllowedFirmware) string {
	if len(in) == 0 {
		return "(none — Download accepts any URL when Download is in RPCs)"
	}
	out := make([]string, len(in))
	sorted := append([]cwmpwrite.AllowedFirmware(nil), in...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].URL < sorted[j].URL })
	for i, f := range sorted {
		if f.SHA256 == "" {
			out[i] = fmt.Sprintf("url=%s", f.URL)
		} else {
			out[i] = fmt.Sprintf("url=%s;sha256=%s", f.URL, f.SHA256)
		}
	}
	return strings.Join(out, ", ")
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

// canonicalCWMPRPCNames is the list of TR-069 §A.4 RPC names
// used for the v1.13 chunk-4 case-warning. Case sensitivity is
// part of the spec, so when an operator types
// `--rpc setparametervalues` we compare lowercase vs lowercase
// and surface the canonical spelling. This list is NOT used by
// the gate (which is strict about case); it's operator-UX
// only.
var canonicalCWMPRPCNames = []string{
	// Read / protocol-flow (already in alwaysSafeRPCs but
	// included so case-warning works even if operator writes
	// them in lowercase).
	"GetRPCMethods",
	"GetParameterNames", "GetParameterNamesResponse",
	"GetParameterValues", "GetParameterValuesResponse",
	"GetParameterAttributes", "GetParameterAttributesResponse",
	"Inform", "InformResponse",
	"TransferComplete", "TransferCompleteResponse",
	"AutonomousTransferComplete",
	"Kicked", "KickedResponse",
	"Fault",
	// Write-capable (the operator-allowlist surface).
	"SetParameterValues", "SetParameterValuesResponse",
	"SetParameterAttributes", "SetParameterAttributesResponse",
	"AddObject", "AddObjectResponse",
	"DeleteObject", "DeleteObjectResponse",
	"Reboot", "RebootResponse",
	"FactoryReset", "FactoryResetResponse",
	"Download", "DownloadResponse",
	"Upload", "UploadResponse",
	"ScheduleInform", "ScheduleInformResponse",
	"ScheduleDownload", "ScheduleDownloadResponse",
	"ChangeDUState", "ChangeDUStateResponse",
	"CancelTransfer", "CancelTransferResponse",
	"GetQueuedTransfers", "GetQueuedTransfersResponse",
	"GetAllQueuedTransfers", "GetAllQueuedTransfersResponse",
	"RequestDownload", "RequestDownloadResponse",
}

// canonicalCWMPRPCByLower maps lowercase canonical name → the
// canonical spelling. Built once, queried by emitCWMPRPCCaseWarnings.
var canonicalCWMPRPCByLower = func() map[string]string {
	m := make(map[string]string, len(canonicalCWMPRPCNames))
	for _, n := range canonicalCWMPRPCNames {
		m[strings.ToLower(n)] = n
	}
	return m
}()

// emitCWMPRPCCaseWarnings prints a one-line warning per RPC
// whose lowercased form matches a canonical TR-069 RPC but
// whose case differs. Silent when the operator's input matches
// canonical case. Silent for RPC names not in the canonical
// list (vendor extensions).
func emitCWMPRPCCaseWarnings(cmd *cobra.Command, in []string) {
	for _, raw := range in {
		r := strings.TrimSpace(raw)
		if i := strings.IndexByte(r, ':'); i > 0 {
			r = r[i+1:]
		}
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		canon, ok := canonicalCWMPRPCByLower[strings.ToLower(r)]
		if !ok {
			continue
		}
		if canon == r {
			continue
		}
		cmd.Printf("warning: --rpc %q differs in case from the canonical TR-069 spelling %q. The CWMP gate is case-sensitive per §A.4 — the wire-side RPC will not match the allowlist.\n", raw, canon)
	}
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

// parseCallMethodFlags parses --call-method entries. Each entry
// is `object=<nodeid>;method=<nodeid>` where each nodeid is
// itself a ns=N;<k>=<v> form — so the flag has nested `;` (one
// separating object= from method=, one inside each NodeId).
// Valid because parseNodeIDFlag already handles a single
// `ns=N;<k>=<v>` string.
func parseCallMethodFlags(in []string) ([]opwrite.AllowedCallMethod, error) {
	out := make([]opwrite.AllowedCallMethod, 0, len(in))
	for _, raw := range in {
		cm, err := parseCallMethodFlag(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, cm)
	}
	return out, nil
}

// parseCallMethodFlag parses one --call-method value into an
// AllowedCallMethod. Splits on the first `;method=` so the
// embedded `;` inside each NodeId doesn't confuse the parser.
func parseCallMethodFlag(s string) (opwrite.AllowedCallMethod, error) {
	raw := strings.TrimSpace(s)
	lower := strings.ToLower(raw)
	if !strings.HasPrefix(lower, "object=") {
		return opwrite.AllowedCallMethod{}, fmt.Errorf("--call-method %q: must start with object=", s)
	}
	rest := raw[len("object="):]
	idx := strings.Index(strings.ToLower(rest), ";method=")
	if idx < 0 {
		return opwrite.AllowedCallMethod{}, fmt.Errorf("--call-method %q: missing ;method=", s)
	}
	objRaw := strings.TrimSpace(rest[:idx])
	mthRaw := strings.TrimSpace(rest[idx+len(";method="):])
	obj, err := canonicalNodeIDForCallMethod(objRaw)
	if err != nil {
		return opwrite.AllowedCallMethod{}, fmt.Errorf("--call-method %q: object: %w", s, err)
	}
	mth, err := canonicalNodeIDForCallMethod(mthRaw)
	if err != nil {
		return opwrite.AllowedCallMethod{}, fmt.Errorf("--call-method %q: method: %w", s, err)
	}
	return opwrite.AllowedCallMethod{ObjectID: obj, MethodID: mth}, nil
}

// canonicalNodeIDForCallMethod canonicalises a NodeId string for
// a CallMethod object/method field, returning the wire-form
// canonical (e.g. numeric 42 normalises to "ns=0;i=42" when no
// ns is provided). Uses parseNodeIDFlag to parse then formats.
func canonicalNodeIDForCallMethod(s string) (string, error) {
	p, err := parseNodeIDFlag(s)
	if err != nil {
		return "", err
	}
	if p.Numeric != nil {
		return fmt.Sprintf("ns=%d;i=%d", p.Numeric.Namespace, p.Numeric.Identifier), nil
	}
	return string(p.Canonical), nil
}

// canonCallMethods prints the sorted list for operator output.
func canonCallMethods(in []opwrite.AllowedCallMethod) string {
	if len(in) == 0 {
		return "(none — CallRequest accepts any object/method when 704 is in services)"
	}
	out := make([]string, len(in))
	sorted := append([]opwrite.AllowedCallMethod(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ObjectID != sorted[j].ObjectID {
			return sorted[i].ObjectID < sorted[j].ObjectID
		}
		return sorted[i].MethodID < sorted[j].MethodID
	})
	for i, cm := range sorted {
		out[i] = fmt.Sprintf("object=%s;method=%s", cm.ObjectID, cm.MethodID)
	}
	return strings.Join(out, ", ")
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
// b= canonical-form entries (see proxyNodeID for schema). v1.12
// chunk 6 adds call_methods for per-CallMethod gating.
func buildAllowFileOPCUA(target string, services []uint, nodeIDRaw, callMethodRaw []string) proxyAllowFile {
	af := proxyAllowFile{
		Plugin:   pluginNameOPCUA,
		Target:   target,
		Services: canonUints(services),
	}
	if len(callMethodRaw) > 0 {
		af.CallMethods = make([]proxyCallMethod, 0, len(callMethodRaw))
		for _, raw := range callMethodRaw {
			cm, err := parseCallMethodFlag(raw)
			if err != nil {
				continue
			}
			af.CallMethods = append(af.CallMethods, proxyCallMethod{
				Object: cm.ObjectID,
				Method: cm.MethodID,
			})
		}
		sort.Slice(af.CallMethods, func(i, j int) bool {
			if af.CallMethods[i].Object != af.CallMethods[j].Object {
				return af.CallMethods[i].Object < af.CallMethods[j].Object
			}
			return af.CallMethods[i].Method < af.CallMethods[j].Method
		})
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

// buildAllowFileBACnet builds the YAML for a BACnet proxy
// session. v1.12 chunk 7 adds `objects:` (type/instance/property
// per entry) for WriteProperty + WritePropertyMultiple. v1.13
// chunk 7 adds `delete_objects:` (type/instance only) for
// DeleteObject (svc 11). v1.13 chunk 8 adds `create_object_types:`
// (type only) for CreateObject (svc 10). v1.13 chunk 9 adds
// `reinit_states:` (state enum) for ReinitializeDevice (svc 20).
func buildAllowFileBACnet(target string, choices []uint, objectsRaw, deleteObjectsRaw []string, createObjectTypes, reinitStates []uint) proxyAllowFile {
	af := proxyAllowFile{
		Plugin:         pluginNameBACnet,
		Target:         target,
		ServiceChoices: canonUints(choices),
	}
	if len(objectsRaw) > 0 {
		af.Objects = make([]proxyBACnetObject, 0, len(objectsRaw))
		for _, raw := range objectsRaw {
			o, err := parseBACnetObjectFlag(raw)
			if err != nil {
				continue
			}
			af.Objects = append(af.Objects, proxyBACnetObject{
				Type:     o.ObjectType,
				Instance: o.ObjectInstance,
				Property: o.PropertyID,
			})
		}
		sort.Slice(af.Objects, func(i, j int) bool {
			if af.Objects[i].Type != af.Objects[j].Type {
				return af.Objects[i].Type < af.Objects[j].Type
			}
			if af.Objects[i].Instance != af.Objects[j].Instance {
				return af.Objects[i].Instance < af.Objects[j].Instance
			}
			return af.Objects[i].Property < af.Objects[j].Property
		})
	}
	if len(deleteObjectsRaw) > 0 {
		af.DeleteObjects = make([]proxyBACnetDeleteObject, 0, len(deleteObjectsRaw))
		for _, raw := range deleteObjectsRaw {
			d, err := parseBACnetDeleteObjectFlag(raw)
			if err != nil {
				continue
			}
			af.DeleteObjects = append(af.DeleteObjects, proxyBACnetDeleteObject{
				Type:     d.ObjectType,
				Instance: d.ObjectInstance,
			})
		}
		sort.Slice(af.DeleteObjects, func(i, j int) bool {
			if af.DeleteObjects[i].Type != af.DeleteObjects[j].Type {
				return af.DeleteObjects[i].Type < af.DeleteObjects[j].Type
			}
			return af.DeleteObjects[i].Instance < af.DeleteObjects[j].Instance
		})
	}
	if len(createObjectTypes) > 0 {
		af.CreateObjectTypes = canonAllowFileBACnetCreateTypes(createObjectTypes)
	}
	if len(reinitStates) > 0 {
		af.ReinitStates = canonAllowFileBACnetReinitStates(reinitStates)
	}
	return af
}

// canonAllowFileBACnetReinitStates converts repeated raw uint
// state values to YAML uint8 entries, dropping out-of-range
// values + sorting ascending. Extracted so buildAllowFileBACnet
// stays under the funlen threshold.
func canonAllowFileBACnetReinitStates(in []uint) []uint8 {
	out := make([]uint8, 0, len(in))
	for _, v := range in {
		if v > 7 {
			continue
		}
		out = append(out, uint8(v&0x07))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// canonAllowFileBACnetCreateTypes converts repeated raw uint
// type values to YAML proxyBACnetCreateObject entries, dropping
// out-of-range values + sorting by ObjectType. Extracted so
// buildAllowFileBACnet stays under the funlen threshold.
func canonAllowFileBACnetCreateTypes(in []uint) []proxyBACnetCreateObject {
	out := make([]proxyBACnetCreateObject, 0, len(in))
	for _, t := range in {
		if t > 0x3FF {
			continue
		}
		out = append(out, proxyBACnetCreateObject{Type: uint16(t & 0x3FF)})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Type < out[j].Type
	})
	return out
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
