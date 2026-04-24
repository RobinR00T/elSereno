//go:build offensive

package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	iaxwire "local/elsereno/internal/protocols/iax2/wire"
	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/internal/proxy"
	"local/elsereno/offensive/confirm"
	bacwrite "local/elsereno/offensive/write/bacnet"
	iaxwrite "local/elsereno/offensive/write/iax2"
	modwrite "local/elsereno/offensive/write/modbus"
	opwrite "local/elsereno/offensive/write/opcua"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	sipwrite "local/elsereno/offensive/write/sip"
)

// newProxyListenCmd runs a gated proxy against a supported
// protocol. The command sits under `elsereno proxy listen` and
// requires both the offensive build tag AND the ADR-039 triple-
// confirm fences for the operator to get past the handler's
// Authorise().
func newProxyListenCmd() *cobra.Command {
	var opts proxyListenOpts
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Run a protocol-aware gated proxy (offensive build)",
		Long: `Binds to --listen and forwards to --target with a
protocol-aware gate. Supported plugins (--plugin):

  sip      method allowlist     (--method INVITE [--method REGISTER...])
  iax2     subclass allowlist   (--subclass NEW [--subclass REGREQ...])
  pbxhttp  (method, path) list  (--allow POST:/path [...])
  modbus   function-code list   (--function 6 [--function 16 ...])
  opcua    service-TypeID list  (--service 673 [--service 704 ...])
  bacnet   service-choice list  (--service-choice 15 [--service-choice 20 ...])

Triple-confirm fences are required (the handler's Authorise()
rejects otherwise):

  --accept-writes
  --confirm-target  (must equal --target byte-for-byte)
  --confirm-token   (derived via ` + "`elsereno write <plugin> dry-run --vault-passphrase-file ...`" + `)
  --vault-passphrase-file <0600 path>  (for audit + key derivation)

The proxy runs until SIGINT / SIGTERM.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxyListen(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.plugin, "plugin", "", "protocol plugin: sip|iax2|pbxhttp")
	cmd.Flags().StringVar(&opts.target, "target", "", "upstream host:port")
	cmd.Flags().StringVar(&opts.listen, "listen", "", "local bind address (e.g. 127.0.0.1:25060)")
	cmd.Flags().StringSliceVar(&opts.methods, "method", nil, "sip: gated methods to allow")
	cmd.Flags().StringSliceVar(&opts.toPrefixes, "to-prefix", nil, "sip: optional INVITE destination allowlist (prefixes like +34, +44). Only applies to INVITE; other methods unaffected (v1.9+).")
	cmd.Flags().StringSliceVar(&opts.subclasses, "subclass", nil, "iax2: gated subclasses to allow (NEW/REGREQ/AUTHREP/ACCEPT)")
	cmd.Flags().StringSliceVar(&opts.allowEntries, "allow", nil, "pbxhttp: METHOD:/path pairs to allow")
	cmd.Flags().UintSliceVar(&opts.functions, "function", nil, "modbus: function codes to allow (e.g. 6 for WriteSingleRegister, 16 for WriteMultipleRegisters)")
	cmd.Flags().UintSliceVar(&opts.services, "service", nil, "opcua: service TypeIDs to allow (e.g. 673 WriteRequest, 704 CallRequest)")
	cmd.Flags().StringSliceVar(&opts.nodeIDs, "node-id", nil, "opcua: optional per-NodeId allowlist (ns=N;i=M form, repeatable). Tightens the gate from service-TypeID to specific NodeIds (v1.6+; numeric encodings only — String/Guid/ByteString fail closed).")
	cmd.Flags().UintSliceVar(&opts.serviceChoices, "service-choice", nil, "bacnet: confirmed-service choices to allow (e.g. 15 WriteProperty, 20 ReinitializeDevice)")
	cmd.Flags().StringVar(&opts.allowFile, "allow-file", "", "read --plugin/--target/allowlist from a YAML file (see docs/manual for schema)")
	cmd.Flags().BoolVar(&opts.acceptWrites, "accept-writes", false, "positive opt-in for real delivery (ADR-039)")
	cmd.Flags().StringVar(&opts.confirmTarget, "confirm-target", "", "must match --target byte-for-byte")
	cmd.Flags().StringVar(&opts.confirmToken, "confirm-token", "", "confirm-token derived from dry-run")
	cmd.Flags().DurationVar(&opts.dialTimeout, "dial-timeout", 5*time.Second, "upstream dial timeout")
	cmd.Flags().DurationVar(&opts.idleTimeout, "idle-timeout", 120*time.Second, "per-connection idle timeout")
	cmd.Flags().IntVar(&opts.maxConns, "max-conns", 0, "max concurrent clients (0 = unlimited)")
	addPassphraseFileFlag(cmd, &opts.ppFile)
	return cmd
}

type proxyListenOpts struct {
	plugin                              string
	target, listen                      string
	methods, subclasses, allowEntries   []string
	functions, services, serviceChoices []uint
	// nodeIDs holds the opcua per-NodeId allowlist in the CLI-
	// friendly "ns=N;i=M" form. Loaded from --node-id flags OR
	// from the allow-file's structured `node_ids:` field (the
	// loader converts structs to this string form). When
	// non-empty, the opcua gate tightens from service-TypeID-
	// only to (service-TypeID + first-WriteValue-NodeId-match).
	nodeIDs []string
	// toPrefixes holds the sip INVITE destination allowlist
	// (v1.9+). E.164-style prefixes (e.g. "+34", "+44") or bare
	// extensions. Empty → v1.4 method-only gating.
	toPrefixes                          []string
	allowFile                           string
	acceptWrites                        bool
	confirmTarget, confirmToken, ppFile string
	dialTimeout, idleTimeout            time.Duration
	maxConns                            int
}

func runProxyListen(cmd *cobra.Command, opts proxyListenOpts) error {
	if opts.allowFile != "" {
		if err := loadAllowFile(opts.allowFile, &opts); err != nil {
			return fail(core.ExitUsage, err)
		}
	}
	if err := validateProxyListenOpts(opts); err != nil {
		return fail(core.ExitUsage, err)
	}

	rt, err := newOffensiveRuntime(cmd, opts.ppFile)
	if err != nil {
		return err
	}
	defer rt.Close()

	c := confirm.Confirm{
		AcceptsWrites: opts.acceptWrites,
		ConfirmTarget: opts.confirmTarget,
		ConfirmToken:  opts.confirmToken,
	}

	handler, err := buildGatedHandler(opts, rt, c)
	if err != nil {
		return fail(core.ExitUsage, err)
	}

	// Authorise now (before the listener binds) so the operator
	// sees token-mismatch errors immediately rather than on the
	// first client connection.
	if err := authoriseHandler(cmd.Context(), handler); err != nil {
		return fail(core.ExitError, fmt.Errorf("authorise: %w", err))
	}

	srv, err := proxy.New(proxy.Options{
		Listen:      opts.listen,
		Upstream:    opts.target,
		Handler:     handler,
		DialTimeout: opts.dialTimeout,
		IdleTimeout: opts.idleTimeout,
		MaxConns:    opts.maxConns,
	})
	if err != nil {
		return fail(core.ExitError, err)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd.Printf("proxy: plugin=%s listen=%s target=%s\n", opts.plugin, opts.listen, opts.target)
	cmd.Printf("proxy: authorised; waiting for client connections (SIGINT to stop)\n")
	cmd.Printf("proxy: audit: %s\n", rt.AuditPath())

	if rerr := srv.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
		return fail(core.ExitError, rerr)
	}
	cmd.Printf("proxy: stopped cleanly\n")
	return nil
}

// validateProxyListenOpts returns a typed error describing the
// first missing required flag, or nil when the options are
// structurally complete.
func validateProxyListenOpts(opts proxyListenOpts) error {
	if opts.target == "" {
		return errors.New("--target is required")
	}
	if opts.listen == "" {
		return errors.New("--listen is required")
	}
	if !opts.acceptWrites {
		return errors.New("--accept-writes is required for real delivery")
	}
	if opts.confirmTarget == "" || opts.confirmToken == "" {
		return errors.New("--confirm-target and --confirm-token are required")
	}
	if opts.ppFile == "" {
		return errors.New("--vault-passphrase-file is required (for key derivation + audit)")
	}
	return nil
}

// gatedProxyHandler bundles the protocol-handler interface with
// its Authorise callback. We need a wrapping interface because
// each write-gate's WriteGatedHandler type is different but they
// all expose the same Authorise + Handle shape.
type gatedProxyHandler interface {
	core.ProxyHandler
	Authorise(ctx context.Context) error
}

// buildGatedHandler dispatches on --plugin (case-folded) to the
// per-plugin constructor. Returning a gatedProxyHandler
// interface lets the caller keep a uniform Authorise() + Handle()
// surface regardless of the concrete plugin type.
func buildGatedHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (gatedProxyHandler, error) {
	switch strings.ToLower(opts.plugin) {
	case pluginNameSIP:
		return buildSIPHandler(opts, rt, c), nil
	case pluginNameIAX2:
		return buildIAX2Handler(opts, rt, c)
	case pluginNamePBXHTTP:
		return buildPBXHTTPHandler(opts, rt, c)
	case pluginNameModbus:
		return buildModbusHandler(opts, rt, c)
	case pluginNameOPCUA:
		return buildOPCUAHandler(opts, rt, c)
	case pluginNameBACnet:
		return buildBACnetHandler(opts, rt, c)
	}
	return nil, fmt.Errorf("--plugin %q: supported values are sip / iax2 / pbxhttp / modbus / opcua / bacnet", opts.plugin)
}

func buildSIPHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) *sipwrite.WriteGatedHandler {
	allowed := make([]sipwrite.AllowedMethod, 0, len(opts.methods))
	for _, m := range opts.methods {
		allowed = append(allowed, sipwrite.AllowedMethod{Method: m})
	}
	prefixes := make([]sipwrite.AllowedToURIPrefix, 0, len(opts.toPrefixes))
	for _, p := range opts.toPrefixes {
		prefixes = append(prefixes, sipwrite.AllowedToURIPrefix{Prefix: p})
	}
	return &sipwrite.WriteGatedHandler{
		Target:               opts.target,
		Allowed:              allowed,
		AllowedToURIPrefixes: prefixes,
		Deriver:              rt.Vault,
		Auditor:              rt.Auditor,
		SessionConfirm:       c,
	}
}

func buildIAX2Handler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*iaxwrite.WriteGatedHandler, error) {
	allowed := make([]iaxwrite.AllowedSubclass, 0, len(opts.subclasses))
	for _, s := range opts.subclasses {
		sub, err := iaxSubclassByName(s)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, iaxwrite.AllowedSubclass{Subclass: sub})
	}
	return &iaxwrite.WriteGatedHandler{
		Target:         opts.target,
		Allowed:        allowed,
		Deriver:        rt.Vault,
		Auditor:        rt.Auditor,
		SessionConfirm: c,
	}, nil
}

func buildPBXHTTPHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*pbxwrite.WriteGatedHandler, error) {
	allowed := make([]pbxwrite.AllowedWrite, 0, len(opts.allowEntries))
	for _, e := range opts.allowEntries {
		aw, err := parseAllowEntry(e)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, aw)
	}
	return &pbxwrite.WriteGatedHandler{
		Target:         opts.target,
		Allowed:        allowed,
		Deriver:        rt.Vault,
		Auditor:        rt.Auditor,
		SessionConfirm: c,
	}, nil
}

func buildModbusHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*modwrite.WriteGatedHandler, error) {
	allowed := make([]modwrite.AllowedWrite, 0, len(opts.functions))
	for _, f := range opts.functions {
		fc, err := parseByteFlag("--function", f)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, modwrite.AllowedWrite{FC: mbwire.FunctionCode(fc)})
	}
	return &modwrite.WriteGatedHandler{
		Target:         opts.target,
		Allowed:        allowed,
		Deriver:        rt.Vault,
		Auditor:        rt.Auditor,
		SessionConfirm: c,
	}, nil
}

func buildOPCUAHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*opwrite.WriteGatedHandler, error) {
	allowed := make([]opwrite.AllowedService, 0, len(opts.services))
	for _, s := range opts.services {
		tid, err := parseUint16Flag("--service", s)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, opwrite.AllowedService{TypeID: tid})
	}
	nodeIDs := make([]opwrite.AllowedNodeID, 0, len(opts.nodeIDs))
	for _, raw := range opts.nodeIDs {
		nid, err := parseNodeIDFlag(raw)
		if err != nil {
			return nil, err
		}
		nodeIDs = append(nodeIDs, nid)
	}
	return &opwrite.WriteGatedHandler{
		Target:         opts.target,
		Allowed:        allowed,
		AllowedNodeIDs: nodeIDs,
		Deriver:        rt.Vault,
		Auditor:        rt.Auditor,
		SessionConfirm: c,
	}, nil
}

func buildBACnetHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*bacwrite.WriteGatedHandler, error) {
	allowed := make([]bacwrite.AllowedService, 0, len(opts.serviceChoices))
	for _, s := range opts.serviceChoices {
		sc, err := parseByteFlag("--service-choice", s)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, bacwrite.AllowedService{ServiceChoice: sc})
	}
	return &bacwrite.WriteGatedHandler{
		Target:         opts.target,
		Allowed:        allowed,
		Deriver:        rt.Vault,
		Auditor:        rt.Auditor,
		SessionConfirm: c,
	}, nil
}

// parseByteFlag validates that a --function / --service-choice
// value fits in a uint8.
func parseByteFlag(name string, v uint) (uint8, error) {
	if v > 0xFF {
		return 0, fmt.Errorf("%s %s: must be 0-255", name, strconv.FormatUint(uint64(v), 10))
	}
	return uint8(v), nil
}

// parseUint16Flag validates that a --service value fits in a uint16.
func parseUint16Flag(name string, v uint) (uint16, error) {
	if v > 0xFFFF {
		return 0, fmt.Errorf("%s %s: must be 0-65535", name, strconv.FormatUint(uint64(v), 10))
	}
	return uint16(v), nil
}

// authoriseHandler calls Authorise on the plugin's handler. All
// gated handlers share the Authorise(ctx) shape.
func authoriseHandler(ctx context.Context, h gatedProxyHandler) error {
	return h.Authorise(ctx)
}

// _ ensure iaxwire is referenced so the import isn't dropped on
// refactors (it's implicitly used via iaxSubclassByName).
var _ = iaxwire.IAXNew
