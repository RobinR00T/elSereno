//go:build offensive

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	opwrite "local/elsereno/offensive/write/opcua"
	uahttpswrite "local/elsereno/offensive/write/opcuahttps"
)

// opcuaHTTPSProxyFlags groups the CLI flags for the OPC UA HTTPS
// proxy-session dry-run. The allowlist flags are identical to the opcua
// (TCP) gate, so an operator writes one allowlist for both transports;
// only the derived token differs (protocol scope).
type opcuaHTTPSProxyFlags struct {
	target, ppFile  string
	services        []uint
	nodeIDs         []string
	callMethods     []string
	tokenGeneration uint32
}

func newWriteOPCUAHTTPSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "opcuahttps",
		Short: "OPC UA HTTPS (Part 6 §7.4) write-gated proxy (proxy-dry-run derives the session confirm-token)",
		Long: `The gated OPC UA HTTPS proxy inspects the bare UA-Binary
message carried in each HTTP POST body (the §7.4 binary binding). It
authorises at the same granularity as the opcua TCP gate: service
TypeID by default, tightened with --node-id (WriteRequest target
NodeIds) and --call-method (CallRequest object/method pairs).

Reads (Read / Browse / GetEndpoints / session management) always pass.
WriteRequest (673) and CallRequest (704) pass only when the service
TypeID is allowed AND, when a per-node / per-method allowlist is set,
every target matches. Unparseable bodies fail closed. A refusal is a
UA ServiceFault (Bad_UserAccessDenied) in an HTTP 200 body.

The token is scoped to protocol "opcuahttps": a token minted for the
opcua TCP gate does NOT authorise this binding, and vice versa.

TLS is a deployment concern (as with the pbxhttp gate): terminate TLS
in front of the gate or point it at a plaintext upstream.`,
	}
	cmd.AddCommand(newWriteOPCUAHTTPSProxyDryRunCmd())
	return cmd
}

func newWriteOPCUAHTTPSProxyDryRunCmd() *cobra.Command {
	var f opcuaHTTPSProxyFlags
	cmd := &cobra.Command{
		Use:   "proxy-dry-run",
		Short: "Proxy-session dry-run: derive the confirm-token for `proxy listen --plugin opcuahttps`",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWriteOPCUAHTTPSProxyDryRun(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.target, "target", "", "upstream host:port (the OPC UA HTTPS server we'll proxy to)")
	cmd.Flags().UintSliceVar(&f.services, "service", nil, "service TypeID(s) to allow (e.g. 673 WriteRequest, 704 CallRequest)")
	cmd.Flags().StringSliceVar(&f.nodeIDs, "node-id", nil, "optional NodeId(s) to restrict WriteRequests to; accepts ns=N;i=M (numeric), ns=N;s=STR (string), ns=N;g=HEX (guid), ns=N;b=HEX (bytestring)")
	cmd.Flags().StringSliceVar(&f.callMethods, "call-method", nil, "optional: per-CallMethod allowlist. Format: object=<NodeId>;method=<NodeId> (each a canonical-string NodeId). Repeatable; exact match only.")
	cmd.Flags().Uint32Var(&f.tokenGeneration, "token-generation", 0, "optional: token-generation cookie. 0 (default) keeps the base hash.")
	addPassphraseFileFlag(cmd, &f.ppFile)
	return cmd
}

func runWriteOPCUAHTTPSProxyDryRun(cmd *cobra.Command, f opcuaHTTPSProxyFlags) error {
	if f.target == "" {
		return fail(core.ExitUsage, errors.New("--target is required"))
	}
	target := canonicaliseTarget(f.target)
	svcs := make([]opwrite.AllowedService, 0, len(f.services))
	for _, s := range f.services {
		if s > 0xFFFF {
			return fail(core.ExitUsage, fmt.Errorf("--service %d: must be 0-65535", s))
		}
		svcs = append(svcs, opwrite.AllowedService{TypeID: uint16(s)}) // #nosec G115 -- bounded above
	}
	nids, canonNids, err := parseNodeIDFlags(f.nodeIDs)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	calls, err := parseCallMethodFlags(f.callMethods)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	mut := uahttpswrite.SessionMutation(target, svcs, nids, canonNids, calls, f.tokenGeneration)
	rows := [][2]string{
		{"Services", canonUintList(f.services)},
		{"NodeIDs", canonNodeIDsRich(nids, canonNids)},
		{"CallMethods", canonCallMethods(calls)},
	}
	if f.tokenGeneration != 0 {
		rows = append(rows, [2]string{"TokenGen", fmt.Sprintf("%d", f.tokenGeneration)})
	}
	// Drop empty rows so the dry-run print stays tidy.
	trimmed := rows[:0]
	for _, r := range rows {
		if strings.TrimSpace(r[1]) != "" {
			trimmed = append(trimmed, r)
		}
	}
	return printProxyDryRun(cmd, "opcuahttps", target, trimmed, mut, f.ppFile)
}
