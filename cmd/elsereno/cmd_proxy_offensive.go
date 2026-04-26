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
	cwmpwrite "local/elsereno/offensive/write/cwmp"
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
	cmd.Flags().StringSliceVar(&opts.aors, "aor", nil, "sip: optional REGISTER AOR allowlist (e.g. sip:alice@pbx.internal, repeatable). Only applies to REGISTER; exact match, not prefix. Registration-hijack mitigation (v1.10+).")
	cmd.Flags().StringSliceVar(&opts.fromDomains, "from-domain", nil, "sip: optional From-header domain allowlist (e.g. internal.pbx, repeatable). Applies to every gated method; exact host match. Identity-spoof mitigation (v1.12+).")
	cmd.Flags().StringSliceVar(&opts.subclasses, "subclass", nil, "iax2: gated subclasses to allow (NEW/REGREQ/AUTHREP/ACCEPT)")
	cmd.Flags().StringSliceVar(&opts.allowEntries, "allow", nil, "pbxhttp: METHOD:/path pairs to allow")
	cmd.Flags().UintSliceVar(&opts.functions, "function", nil, "modbus: function codes to allow (e.g. 6 for WriteSingleRegister, 16 for WriteMultipleRegisters). Legacy form — any unit, any address. For per-entry unit+FC+address-range tightening use --write instead.")
	cmd.Flags().StringSliceVar(&opts.modbusWritesCLI, "write", nil, "modbus: structured allowlist entry unit=N;fc=M;start=A;end=B (repeatable). unit/start/end are optional (0 = any). Example: unit=1;fc=6;start=100;end=200. v1.12+.")
	cmd.Flags().UintSliceVar(&opts.services, "service", nil, "opcua: service TypeIDs to allow (e.g. 673 WriteRequest, 704 CallRequest)")
	cmd.Flags().StringSliceVar(&opts.nodeIDs, "node-id", nil, "opcua: optional per-NodeId allowlist (repeatable). Accepts ns=N;i=M (numeric), ns=N;s=STR (string), ns=N;g=HEX (guid), ns=N;b=HEX (bytestring). Tightens the gate from service-TypeID to specific NodeIds; v1.12+ walks every WriteValue in a batched WriteRequest (v1.6 chunk 2 only checked the first).")
	cmd.Flags().StringSliceVar(&opts.callMethods, "call-method", nil, "opcua: optional per-CallMethod allowlist (repeatable). Format: object=<NodeId>;method=<NodeId> where each NodeId is canonical-string form (ns=N;{i,s,g,b}=…). Restricts CallRequest to specific (object, method) pairs; exact match only. v1.12+.")
	cmd.Flags().UintSliceVar(&opts.serviceChoices, "service-choice", nil, "bacnet: confirmed-service choices to allow (e.g. 15 WriteProperty, 20 ReinitializeDevice)")
	cmd.Flags().StringSliceVar(&opts.bacnetObjects, "object", nil, "bacnet: optional per-object allowlist for WriteProperty (svc 15, v1.12+) and WritePropertyMultiple (svc 16, v1.13+). Format: type=N;instance=M;property=P (repeatable, exact match). Both gates walk every (object, property) tuple in the request. Other mutating services keep service-only gating.")
	cmd.Flags().StringSliceVar(&opts.bacnetDeleteObjects, "delete-object", nil, "bacnet: optional per-target allowlist for DeleteObject (svc 11, v1.13+). Format: type=N;instance=M (repeatable, exact match). Object-level only.")
	cmd.Flags().UintSliceVar(&opts.bacnetCreateObjectTypes, "create-object-type", nil, "bacnet: optional per-type allowlist for CreateObject (svc 10, v1.13+). Numeric BACnetObjectType (e.g. 17 for Schedule, 19 for MultiStateValue). Type-only — instance ignored at gate level.")
	cmd.Flags().UintSliceVar(&opts.bacnetReinitStates, "reinit-state", nil, "bacnet: optional per-state allowlist for ReinitializeDevice (svc 20, v1.13+). Numeric reinitializedStateOfDevice enum (0 coldstart, 1 warmstart, 2..6 backup/restore, 7 activate-changes). Operator typically allows only 7.")
	cmd.Flags().UintSliceVar(&opts.bacnetDCCStates, "dcc-state", nil, "bacnet: optional per-state allowlist for DeviceCommunicationControl (svc 17, v1.13+). Numeric enableDisable enum (0 enable, 1 disable, 2 disableInitiation). Operator typically allows only 0 (recovery from attacker-induced silence) and refuses 1/2.")
	cmd.Flags().UintSliceVar(&opts.bacnetLSOOps, "lso-op", nil, "bacnet: optional per-operation allowlist for LifeSafetyOperation (svc 27, v1.13+). Numeric BACnetLifeSafetyOperation enum (0 none, 1/2/3 silence variants — POTENTIALLY LETHAL on fire-alarm panels, 4/5/6 reset variants, 7/8/9 unsilence variants). Operator typically allows 7/8/9 freely + 4/5/6 case-by-case + REFUSES 1/2/3 outright on production life-safety buses.")
	cmd.Flags().StringSliceVar(&opts.rpcs, "rpc", nil, "cwmp: SOAP RPC name(s) to allow (e.g. SetParameterValues, Reboot, FactoryReset). Case-sensitive per TR-069 §A.4; \"cwmp:\" prefix tolerated. Read-only + protocol-flow RPCs (GetParameter*, Inform, TransferComplete, …) always pass (v1.11+).")
	cmd.Flags().StringSliceVar(&opts.paramPrefixes, "param-prefix", nil, "cwmp: optional per-parameter-path allowlist — prefixes like \"InternetGatewayDevice.WANDevice.\" constrain Set* RPCs to specific sub-trees. Every Name in the request must match at least one prefix. Case-sensitive per TR-069 data model. Non-Set RPCs unaffected (v1.12+).")
	cmd.Flags().StringSliceVar(&opts.cwmpFirmware, "firmware", nil, "cwmp: optional per-image allowlist for Download RPC. Format: url=<full-url>;sha256=<hex> (sha256 optional; repeatable). URL must EXACTLY match the <URL> the ACS sends. SHA256 is metadata for downstream verification (not enforced at RPC time — TR-069 doesn't carry it). v1.12+.")
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
	// cwmpFirmware holds the cwmp per-image allowlist for the
	// Download RPC in CLI-friendly "url=<u>;sha256=<hex>" form
	// (v1.12+). Restricts Download to specific firmware URLs;
	// SHA256 is metadata only (TR-069 reports it later via
	// TransferComplete).
	cwmpFirmware []string
	// bacnetObjects holds the bacnet per-object WriteProperty
	// allowlist in the CLI-friendly
	// "type=N;instance=M;property=P" form (v1.12+). Restricts
	// service 15 WriteProperty (and v1.13+ service 16
	// WritePropertyMultiple) requests to specific
	// (ObjectType, ObjectInstance, PropertyID) tuples.
	bacnetObjects []string
	// bacnetDeleteObjects holds the bacnet per-target
	// DeleteObject allowlist in the CLI-friendly
	// "type=N;instance=M" form (v1.13+). Object-level only —
	// PropertyID doesn't apply to deletion. Restricts service
	// 11 DeleteObject requests to specific (ObjectType,
	// ObjectInstance) pairs.
	bacnetDeleteObjects []string
	// bacnetCreateObjectTypes holds the bacnet per-type
	// CreateObject allowlist (v1.13+). Numeric BACnetObjectType
	// values (10-bit). When non-empty, CreateObject (svc 10)
	// requests are forwarded only when the inferred ObjectType
	// matches one of these entries (instance is ignored).
	bacnetCreateObjectTypes []uint
	// bacnetReinitStates holds the bacnet per-state
	// ReinitializeDevice allowlist (v1.13+). Numeric ASHRAE 135
	// §16.4 reinitializedStateOfDevice enum (0..7). When
	// non-empty, ReinitializeDevice (svc 20) requests forward
	// only when the parsed state value matches one of these.
	bacnetReinitStates []uint
	// bacnetDCCStates holds the bacnet per-state
	// DeviceCommunicationControl allowlist (v1.13+). Numeric
	// ASHRAE 135 §16.1 enableDisable enum (0..2). When
	// non-empty, DeviceCommunicationControl (svc 17) requests
	// forward only when the parsed state value matches one of
	// these.
	bacnetDCCStates []uint
	// bacnetLSOOps holds the bacnet per-operation
	// LifeSafetyOperation allowlist (v1.13+). Numeric ASHRAE
	// 135 §21 BACnetLifeSafetyOperation enum (0..9). When
	// non-empty, LifeSafetyOperation (svc 27) requests forward
	// only when the parsed operation value matches one of
	// these. CRITICAL for life-safety systems: silencing
	// operations can be life-threatening on production
	// fire-alarm panels.
	bacnetLSOOps []uint
	// callMethods holds the opcua per-CallMethod allowlist in
	// the CLI-friendly "object=<NodeId>;method=<NodeId>" form
	// (v1.12+). When non-empty, a CallRequest MSG is forwarded
	// only when every CallMethodRequest's (ObjectId, MethodId)
	// pair matches one of these entries.
	callMethods []string
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
	toPrefixes []string
	// aors holds the sip REGISTER AOR allowlist (v1.10+). Full
	// AoRs (e.g. "sip:alice@pbx.internal") — exact-match after
	// canonicalisation. Empty → v1.9 (or v1.4) gating without
	// AOR-level tightening.
	aors []string
	// fromDomains holds the sip From-header domain allowlist
	// (v1.12+). Host names (e.g. "internal.pbx") — exact-match
	// after canonicalisation, applied to every gated method.
	// Empty → v1.10 (or earlier) gating without from-domain
	// tightening.
	fromDomains []string
	// rpcs holds the cwmp SOAP RPC allowlist (v1.11+). RPC
	// names (e.g. "SetParameterValues", "Reboot") — case-
	// sensitive per TR-069 §A.4. Empty → only read-only +
	// protocol-flow RPCs pass; every write-capable RPC refused.
	rpcs []string
	// paramPrefixes holds the cwmp per-parameter-path
	// allowlist (v1.12+). TR-069 parameter-name prefixes (e.g.
	// "InternetGatewayDevice.WANDevice.") that constrain Set*
	// RPCs to specific sub-trees. Case-sensitive. Empty → RPC-
	// only gating (v1.11 behaviour).
	paramPrefixes []string
	// modbusWritesCLI holds structured --write flag values in
	// their CLI string form ("unit=N;fc=M;start=A;end=B"). v1.12
	// chunk 4 adds per-entry unit+FC+address-range granularity.
	// Parsed in buildModbusHandler; merged with opts.functions.
	modbusWritesCLI []string
	// modbusWritesYAML holds structured entries loaded from the
	// allow-file's `writes:` field. Kept separate from CLI so the
	// loader can overwrite without losing the legacy functions
	// list (which may also be present in the same YAML).
	modbusWritesYAML                    []proxyModbusWrite
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
	case pluginNameCWMP:
		h, err := buildCWMPHandler(opts, rt, c)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	return nil, fmt.Errorf("--plugin %q: supported values are sip / iax2 / pbxhttp / modbus / opcua / bacnet / cwmp", opts.plugin)
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
	aors := make([]sipwrite.AllowedAOR, 0, len(opts.aors))
	for _, a := range opts.aors {
		aors = append(aors, sipwrite.AllowedAOR{AOR: a})
	}
	fromDomains := make([]sipwrite.AllowedFromDomain, 0, len(opts.fromDomains))
	for _, d := range opts.fromDomains {
		fromDomains = append(fromDomains, sipwrite.AllowedFromDomain{Domain: d})
	}
	return &sipwrite.WriteGatedHandler{
		Target:               opts.target,
		Allowed:              allowed,
		AllowedToURIPrefixes: prefixes,
		AllowedAORs:          aors,
		AllowedFromDomains:   fromDomains,
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
	allowed, err := buildModbusAllowlist(opts)
	if err != nil {
		return nil, err
	}
	return &modwrite.WriteGatedHandler{
		Target:         opts.target,
		Allowed:        allowed,
		Deriver:        rt.Vault,
		Auditor:        rt.Auditor,
		SessionConfirm: c,
	}, nil
}

// buildModbusAllowlist merges the three input sources a proxy-
// listen session can carry: legacy --function FC list, the v1.12
// --write structured flags, and the allow-file's `writes:` YAML
// entries. Produces the flat []AllowedWrite the library expects.
func buildModbusAllowlist(opts proxyListenOpts) ([]modwrite.AllowedWrite, error) {
	allowed := make([]modwrite.AllowedWrite, 0,
		len(opts.functions)+len(opts.modbusWritesCLI)+len(opts.modbusWritesYAML))
	for _, f := range opts.functions {
		fc, err := parseByteFlag("--function", f)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, modwrite.AllowedWrite{FC: mbwire.FunctionCode(fc)})
	}
	for _, raw := range opts.modbusWritesCLI {
		w, err := parseModbusWriteFlag(raw)
		if err != nil {
			return nil, err
		}
		allowed = append(allowed, w)
	}
	for _, w := range opts.modbusWritesYAML {
		allowed = append(allowed, modwrite.AllowedWrite{
			Unit:      w.Unit,
			FC:        mbwire.FunctionCode(w.FC),
			StartAddr: w.Start,
			EndAddr:   w.End,
		})
	}
	return allowed, nil
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
	nodeIDs, canonNodeIDs, err := parseNodeIDFlags(opts.nodeIDs)
	if err != nil {
		return nil, err
	}
	calls, err := parseCallMethodFlags(opts.callMethods)
	if err != nil {
		return nil, err
	}
	return &opwrite.WriteGatedHandler{
		Target:                  opts.target,
		Allowed:                 allowed,
		AllowedNodeIDs:          nodeIDs,
		AllowedCanonicalNodeIDs: canonNodeIDs,
		AllowedCallMethods:      calls,
		Deriver:                 rt.Vault,
		Auditor:                 rt.Auditor,
		SessionConfirm:          c,
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
	objs, err := parseBACnetObjectFlags(opts.bacnetObjects)
	if err != nil {
		return nil, err
	}
	delObjs, err := parseBACnetDeleteObjectFlags(opts.bacnetDeleteObjects)
	if err != nil {
		return nil, err
	}
	creObjs, err := parseBACnetCreateObjectTypes(opts.bacnetCreateObjectTypes)
	if err != nil {
		return nil, err
	}
	reiSts, err := parseBACnetReinitStates(opts.bacnetReinitStates)
	if err != nil {
		return nil, err
	}
	dccSts, err := parseBACnetDCCStates(opts.bacnetDCCStates)
	if err != nil {
		return nil, err
	}
	lsoOps, err := parseBACnetLSOOps(opts.bacnetLSOOps)
	if err != nil {
		return nil, err
	}
	return &bacwrite.WriteGatedHandler{
		Target:               opts.target,
		Allowed:              allowed,
		AllowedObjects:       objs,
		AllowedDeleteObjects: delObjs,
		AllowedCreateObjects: creObjs,
		AllowedReinitStates:  reiSts,
		AllowedDCCStates:     dccSts,
		AllowedLSOOperations: lsoOps,
		Deriver:              rt.Vault,
		Auditor:              rt.Auditor,
		SessionConfirm:       c,
	}, nil
}

// buildCWMPHandler wires opts.rpcs onto a CWMP WriteGatedHandler.
// Read-only / protocol-flow RPCs are hardcoded in the library's
// alwaysSafeRPCs set and don't need to pass through here — the
// operator only supplies the write-capable RPCs they want to
// authorise (SetParameterValues, Reboot, Download, etc.).
func buildCWMPHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*cwmpwrite.WriteGatedHandler, error) {
	allowed := make([]cwmpwrite.AllowedRPC, 0, len(opts.rpcs))
	for _, r := range opts.rpcs {
		allowed = append(allowed, cwmpwrite.AllowedRPC{Name: r})
	}
	paths := make([]cwmpwrite.AllowedParameterPath, 0, len(opts.paramPrefixes))
	for _, p := range opts.paramPrefixes {
		paths = append(paths, cwmpwrite.AllowedParameterPath{Prefix: p})
	}
	firmware, err := parseCWMPFirmwareFlags(opts.cwmpFirmware)
	if err != nil {
		return nil, err
	}
	return &cwmpwrite.WriteGatedHandler{
		Target:                opts.target,
		Allowed:               allowed,
		AllowedParameterPaths: paths,
		AllowedFirmware:       firmware,
		Deriver:               rt.Vault,
		Auditor:               rt.Auditor,
		SessionConfirm:        c,
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
