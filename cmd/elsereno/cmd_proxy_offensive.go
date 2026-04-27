//go:build offensive

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
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

The proxy runs until SIGINT / SIGTERM (clean shutdown, exit 0)
or SIGHUP (reload-style exit 75 / EX_TEMPFAIL). The SIGHUP path
is for operators wrapping the proxy in a supervisor (systemd
` + "`Restart=always`" + `, runit, s6, etc.): edit the allow-file, mint
a fresh confirm-token, then ` + "`kill -HUP`" + ` — the supervisor
restarts the proxy and the new instance picks up the updated
config.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProxyListen(cmd, opts)
		},
	}
	registerProxyListenFlags(cmd, &opts)
	return cmd
}

// registerProxyListenFlags registers every CLI flag onto cmd.
// Extracted from newProxyListenCmd so the parent function stays
// under funlen as we keep adding per-service dimensions.
func registerProxyListenFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().StringVar(&opts.plugin, "plugin", "", "protocol plugin: sip|iax2|pbxhttp")
	cmd.Flags().StringVar(&opts.target, "target", "", "upstream host:port")
	cmd.Flags().StringVar(&opts.listen, "listen", "", "local bind address (e.g. 127.0.0.1:25060)")
	registerProxyListenSIPFlags(cmd, opts)
	registerProxyListenIAX2PBXFlags(cmd, opts)
	registerProxyListenModbusFlags(cmd, opts)
	registerProxyListenOPCUAFlags(cmd, opts)
	registerProxyListenBACnetFlags(cmd, opts)
	registerProxyListenCWMPFlags(cmd, opts)
	registerProxyListenSessionFlags(cmd, opts)
	addPassphraseFileFlag(cmd, &opts.ppFile)
}

// registerProxyListenSIPFlags adds the sip-specific flags.
func registerProxyListenSIPFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().StringSliceVar(&opts.methods, "method", nil, "sip: gated methods to allow")
	cmd.Flags().StringSliceVar(&opts.toPrefixes, "to-prefix", nil, "sip: optional INVITE destination allowlist (prefixes like +34, +44). Only applies to INVITE; other methods unaffected (v1.9+).")
	cmd.Flags().StringSliceVar(&opts.aors, "aor", nil, "sip: optional REGISTER AOR allowlist (e.g. sip:alice@pbx.internal, repeatable). Only applies to REGISTER; exact match, not prefix. Registration-hijack mitigation (v1.10+).")
	cmd.Flags().StringSliceVar(&opts.fromDomains, "from-domain", nil, "sip: optional From-header domain allowlist (e.g. internal.pbx, repeatable). Applies to every gated method; exact host match. Identity-spoof mitigation (v1.12+).")
}

// registerProxyListenIAX2PBXFlags adds iax2 + pbxhttp flags.
func registerProxyListenIAX2PBXFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().StringSliceVar(&opts.subclasses, "subclass", nil, "iax2: gated subclasses to allow (NEW/REGREQ/AUTHREP/ACCEPT)")
	cmd.Flags().StringSliceVar(&opts.allowEntries, "allow", nil, "pbxhttp: METHOD:/path pairs to allow")
}

// registerProxyListenModbusFlags adds the modbus flags.
func registerProxyListenModbusFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().UintSliceVar(&opts.functions, "function", nil, "modbus: function codes to allow (e.g. 6 for WriteSingleRegister, 16 for WriteMultipleRegisters). Legacy form — any unit, any address. For per-entry unit+FC+address-range tightening use --write instead.")
	cmd.Flags().StringSliceVar(&opts.modbusWritesCLI, "write", nil, "modbus: structured allowlist entry unit=N;fc=M;start=A;end=B (repeatable). unit/start/end are optional (0 = any). Example: unit=1;fc=6;start=100;end=200. v1.12+.")
}

// registerProxyListenOPCUAFlags adds the opcua flags.
func registerProxyListenOPCUAFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().UintSliceVar(&opts.services, "service", nil, "opcua: service TypeIDs to allow (e.g. 673 WriteRequest, 704 CallRequest)")
	cmd.Flags().StringSliceVar(&opts.nodeIDs, "node-id", nil, "opcua: optional per-NodeId allowlist (repeatable). Accepts ns=N;i=M (numeric), ns=N;s=STR (string), ns=N;g=HEX (guid), ns=N;b=HEX (bytestring). Tightens the gate from service-TypeID to specific NodeIds; v1.12+ walks every WriteValue in a batched WriteRequest (v1.6 chunk 2 only checked the first).")
	cmd.Flags().StringSliceVar(&opts.callMethods, "call-method", nil, "opcua: optional per-CallMethod allowlist (repeatable). Format: object=<NodeId>;method=<NodeId> where each NodeId is canonical-string form (ns=N;{i,s,g,b}=…). Restricts CallRequest to specific (object, method) pairs; exact match only. v1.12+.")
}

// registerProxyListenBACnetFlags adds the bacnet flags.
func registerProxyListenBACnetFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().UintSliceVar(&opts.serviceChoices, "service-choice", nil, "bacnet: confirmed-service choices to allow (e.g. 15 WriteProperty, 20 ReinitializeDevice)")
	cmd.Flags().StringSliceVar(&opts.bacnetObjects, "object", nil, "bacnet: optional per-object allowlist for WriteProperty (svc 15, v1.12+) and WritePropertyMultiple (svc 16, v1.13+). Format: type=N;instance=M;property=P (repeatable, exact match). Both gates walk every (object, property) tuple in the request. Other mutating services keep service-only gating.")
	cmd.Flags().StringSliceVar(&opts.bacnetDeleteObjects, "delete-object", nil, "bacnet: optional per-target allowlist for DeleteObject (svc 11, v1.13+). Format: type=N;instance=M (repeatable, exact match). Object-level only.")
	cmd.Flags().UintSliceVar(&opts.bacnetCreateObjectTypes, "create-object-type", nil, "bacnet: optional per-type allowlist for CreateObject (svc 10, v1.13+). Numeric BACnetObjectType (e.g. 17 for Schedule, 19 for MultiStateValue). Type-only — instance ignored at gate level. Pair with --create-object-instance for per-(type,instance) tightening (v1.16+).")
	cmd.Flags().StringSliceVar(&opts.bacnetCreateObjectInstances, "create-object-instance", nil, "bacnet: optional per-(type, instance) allowlist for CreateObject (svc 10, v1.16+). Format: type=N;instance=M (repeatable, exact match). Refines --create-object-type when the ACS uses the [1] objectIdentifier CHOICE form (operator pre-declares which exact instance the device should create). When this list is set AND the request uses CHOICE [0] objectType (no explicit instance), the per-type list governs.")
	cmd.Flags().UintSliceVar(&opts.bacnetReinitStates, "reinit-state", nil, "bacnet: optional per-state allowlist for ReinitializeDevice (svc 20, v1.13+). Numeric reinitializedStateOfDevice enum (0 coldstart, 1 warmstart, 2..6 backup/restore, 7 activate-changes). Operator typically allows only 7.")
	cmd.Flags().UintSliceVar(&opts.bacnetDCCStates, "dcc-state", nil, "bacnet: optional per-state allowlist for DeviceCommunicationControl (svc 17, v1.13+). Numeric enableDisable enum (0 enable, 1 disable, 2 disableInitiation). Operator typically allows only 0 (recovery from attacker-induced silence) and refuses 1/2.")
	cmd.Flags().UintSliceVar(&opts.bacnetLSOOps, "lso-op", nil, "bacnet: optional per-operation allowlist for LifeSafetyOperation (svc 27, v1.13+). Numeric BACnetLifeSafetyOperation enum (0 none, 1/2/3 silence variants — POTENTIALLY LETHAL on fire-alarm panels, 4/5/6 reset variants, 7/8/9 unsilence variants). Operator typically allows 7/8/9 freely + 4/5/6 case-by-case + REFUSES 1/2/3 outright on production life-safety buses. Pair with --lso-target for per-(op, type, instance) tightening (v1.16+).")
	cmd.Flags().StringSliceVar(&opts.bacnetLSOTargets, "lso-target", nil, "bacnet: optional per-(operation, type, instance) allowlist for LifeSafetyOperation (svc 27, v1.16+). Format: op=N;type=N;instance=N (repeatable, exact match). Refines --lso-op when the ACS includes the [3] objectIdentifier (operator-scoped LSO at a specific Life-Safety-Point object). Per-target match wins; falls back to --lso-op for device-wide requests (those without [3]).")
	cmd.Flags().UintSliceVar(&opts.bacnetAWFFiles, "awf-file", nil, "bacnet: optional per-File-instance allowlist for AtomicWriteFile (svc 7, v1.13+). Numeric File-object instance number (ObjectType implicitly 10 = File). Restricts file overwrites to specific File instances — useful when File#1 is firmware blob and File#5 is a log file; allow log writes but refuse firmware overwrites.")
	cmd.Flags().StringSliceVar(&opts.bacnetListElements, "list-element", nil, "bacnet: optional per-(object, property) allowlist for AddListElement (svc 8) AND RemoveListElement (svc 9, v1.13+). Format: type=N;instance=M;property=P (repeatable, exact match). Same shape as --object but applies only to the list-mutation services. Common targets: NotificationClass#N.recipient_list (102), Schedule#N.exception_schedule (38).")
}

// registerProxyListenCWMPFlags adds the cwmp flags.
func registerProxyListenCWMPFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().StringSliceVar(&opts.rpcs, "rpc", nil, "cwmp: SOAP RPC name(s) to allow (e.g. SetParameterValues, Reboot, FactoryReset). Case-sensitive per TR-069 §A.4; \"cwmp:\" prefix tolerated. Read-only + protocol-flow RPCs (GetParameter*, Inform, TransferComplete, …) always pass (v1.11+).")
	cmd.Flags().StringSliceVar(&opts.paramPrefixes, "param-prefix", nil, "cwmp: optional per-parameter-path allowlist — prefixes like \"InternetGatewayDevice.WANDevice.\" constrain Set* RPCs to specific sub-trees. Every Name in the request must match at least one prefix. Case-sensitive per TR-069 data model. Non-Set RPCs unaffected (v1.12+).")
	cmd.Flags().StringSliceVar(&opts.cwmpFirmware, "firmware", nil, "cwmp: optional per-image allowlist for Download RPC. Format: url=<full-url>;sha256=<hex> (sha256 optional; repeatable). URL must EXACTLY match the <URL> the ACS sends. SHA256 is metadata for downstream verification (not enforced at RPC time — TR-069 doesn't carry it). v1.12+.")
}

// registerProxyListenSessionFlags adds the session-control
// flags (allow-file, accept-writes, confirm-target/token,
// timeouts, max-conns).
func registerProxyListenSessionFlags(cmd *cobra.Command, opts *proxyListenOpts) {
	cmd.Flags().StringVar(&opts.allowFile, "allow-file", "", "read --plugin/--target/allowlist from a YAML file (see docs/manual for schema)")
	cmd.Flags().BoolVar(&opts.acceptWrites, "accept-writes", false, "positive opt-in for real delivery (ADR-039)")
	cmd.Flags().StringVar(&opts.confirmTarget, "confirm-target", "", "must match --target byte-for-byte")
	cmd.Flags().StringVar(&opts.confirmToken, "confirm-token", "", "confirm-token derived from dry-run")
	cmd.Flags().DurationVar(&opts.dialTimeout, "dial-timeout", 5*time.Second, "upstream dial timeout")
	cmd.Flags().DurationVar(&opts.idleTimeout, "idle-timeout", 120*time.Second, "per-connection idle timeout")
	cmd.Flags().IntVar(&opts.maxConns, "max-conns", 0, "max concurrent clients (0 = unlimited)")
	cmd.Flags().BoolVar(&opts.reloadAllowFile, "reload-allow-file", false, "v1.17+: enable in-process SIGUSR1 reload of --allow-file. On SIGUSR1 the proxy re-reads the allow-file, re-reads the sidecar `<allow-file>.token` (0600) for the new confirm-token, builds + authorises the new handler, and atomically swaps it. In-flight connections finish with the old allowlist; new connections use the new. Requires --allow-file. Mutually-exclusive with the v1.15 SIGHUP supervisor-restart pattern only insofar as SIGHUP still exits 75 — operators choose: USR1 in-process or HUP supervisor restart.")
	// Shared across plugins that ship a token-generation cookie
	// (v1.16+ for bacnet; v1.17+ adding cwmp + others). Each
	// plugin's handler builder picks this up — only the active
	// --plugin's gate consumes it. Folds into the session hash
	// so confirm-tokens minted with a different generation are
	// rejected.
	cmd.Flags().Uint32Var(&opts.tokenGeneration, "token-generation", 0, "optional: token-generation cookie (v1.16+ bacnet, v1.17+ all 7 write-gated plugins). Folds into the session hash so a confirm-token minted with a different generation is rejected. Bump on allow-file edit to invalidate stale tokens — the cryptographic foundation for in-process allow-file reload (paired with --reload-allow-file). 0 (default) preserves the prior-cycle hash for backwards-compat. Plugins without per-plugin generation support ignore this flag.")
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
	// tokenGeneration is the shared --token-generation cookie
	// (v1.16+ for bacnet; v1.17+ for cwmp; rolling out to
	// other plugins as cycles proceed). Each plugin's handler
	// builder picks this up; plugins without generation support
	// ignore it.
	tokenGeneration uint32
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
	// bacnetCreateObjectInstances holds the bacnet per-(type,
	// instance) CreateObject allowlist (v1.16+). Each entry is
	// a "type=N;instance=M" string. Refines the per-type list
	// for CHOICE [1] objectIdentifier requests where the ACS
	// pre-declares which exact instance the device should
	// create.
	bacnetCreateObjectInstances []string
	// bacnetLSOTargets holds the bacnet per-(operation, type,
	// instance) LifeSafetyOperation allowlist (v1.16+). Each
	// entry is an "op=N;type=N;instance=N" string. Refines the
	// per-operation list when the ACS includes the [3]
	// objectIdentifier on a per-LSP-scoped request.
	bacnetLSOTargets []string
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
	// bacnetAWFFiles holds the bacnet per-File-instance
	// AtomicWriteFile allowlist (v1.13+). 22-bit File-object
	// instance number (ObjectType implicitly 10 = File). When
	// non-empty, AtomicWriteFile (svc 7) requests forward only
	// when the parsed fileIdentifier's instance matches one of
	// these.
	bacnetAWFFiles []uint
	// bacnetListElements holds the bacnet per-(object, property)
	// allowlist for AddListElement (svc 8) AND RemoveListElement
	// (svc 9), v1.13+. CLI-friendly "type=N;instance=M;property=P"
	// form. When non-empty, both services forward only when the
	// parsed (type, instance, property) tuple matches one of
	// these entries.
	bacnetListElements []string
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
	// reloadAllowFile enables the v1.17 chunk-4 SIGUSR1
	// in-process reload. Requires allowFile to be set.
	reloadAllowFile bool
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
	// Canonicalise the IP-literal forms in target / listen /
	// confirmTarget so an operator who wrote
	// `[0:0:0:0:0:0:0:1]:7547` in dry-run + `[::1]:7547` in
	// proxy listen sees both normalise to the same value (token
	// matches, byte-for-byte compare succeeds). v1.14 chunk 2.
	opts.target = canonicaliseTarget(opts.target)
	opts.listen = canonicaliseTarget(opts.listen)
	opts.confirmTarget = canonicaliseTarget(opts.confirmTarget)

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

	// v1.17 chunk 4: when --reload-allow-file is set, wrap the
	// handler in a reloadableHandler so SIGUSR1 can swap the
	// allowlist atomically. Plain runs (no flag) install the
	// concrete handler directly — same as pre-v1.17 behaviour.
	servedHandler := wrapForReload(opts, handler)

	srv, err := proxy.New(proxy.Options{
		Listen:      opts.listen,
		Upstream:    opts.target,
		Handler:     servedHandler,
		DialTimeout: opts.dialTimeout,
		IdleTimeout: opts.idleTimeout,
		MaxConns:    opts.maxConns,
	})
	if err != nil {
		return fail(core.ExitError, err)
	}
	return runProxyServer(cmd, opts, rt, srv, servedHandler)
}

// runProxyServer wires the signal handlers (SIGINT/SIGTERM/SIGHUP
// + v1.17-chunk-4 SIGUSR1) and runs the proxy.Server. Extracted
// from runProxyListen so the parent stays under funlen as the
// chunk-4 reload-watcher plumbing adds branches.
func runProxyServer(cmd *cobra.Command, opts proxyListenOpts, rt *offensiveRuntime, srv *proxy.Server, servedHandler gatedProxyHandler) error {
	// v1.15 chunk 5: distinguish SIGHUP (reload-style exit 75)
	// from SIGINT/SIGTERM (clean exit 0). Wrap the existing
	// signal.NotifyContext with a side-channel that captures
	// which signal fired; we still cancel the same context so
	// the server-stop path is unchanged.
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)

	// v1.17 chunk 4: SIGUSR1 → in-process reload. Only active
	// when --reload-allow-file is set (signalled by servedHandler
	// being a *reloadableHandler).
	if reloader, ok := servedHandler.(*reloadableHandler); ok {
		startReloadWatcher(ctx, cmd, opts, rt, reloader)
	}

	cmd.Printf("proxy: plugin=%s listen=%s target=%s\n", opts.plugin, opts.listen, opts.target)
	if opts.reloadAllowFile {
		cmd.Printf("proxy: authorised; waiting for client connections (SIGINT/SIGTERM stop, SIGHUP supervisor-reload, SIGUSR1 in-process reload of --allow-file via sidecar token)\n")
	} else {
		cmd.Printf("proxy: authorised; waiting for client connections (SIGINT/SIGTERM stop, SIGHUP reloads via supervisor restart)\n")
	}
	cmd.Printf("proxy: audit: %s\n", rt.AuditPath())

	if rerr := srv.Run(ctx); rerr != nil && !errors.Is(rerr, context.Canceled) {
		return fail(core.ExitError, rerr)
	}
	return finishProxyListen(cmd, hupCh)
}

// wrapForReload returns a gatedProxyHandler suitable for
// proxy.Server. When --reload-allow-file is set, returns a
// reloadableHandler wrapping h. Otherwise returns h directly
// so non-reload runs are byte-identical to pre-v1.17 behaviour.
func wrapForReload(opts proxyListenOpts, h gatedProxyHandler) gatedProxyHandler {
	if !opts.reloadAllowFile {
		return h
	}
	return newReloadableHandler(h)
}

// startReloadWatcher spawns a goroutine that listens for
// SIGUSR1 and triggers performReload. The goroutine exits when
// ctx is canceled. v1.17 chunk 4.
//
// On reload failure the old handler stays installed; the
// operator sees the failure on stderr and can retry after
// fixing the allow-file or sidecar token.
func startReloadWatcher(ctx context.Context, cmd *cobra.Command, opts proxyListenOpts, rt *offensiveRuntime, target *reloadableHandler) {
	usrCh := make(chan os.Signal, 1)
	signal.Notify(usrCh, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(usrCh)
		for {
			select {
			case <-ctx.Done():
				return
			case <-usrCh:
				if err := performReload(ctx, cmd, opts, rt, target); err != nil {
					cmd.PrintErrf("proxy: SIGUSR1 reload failed: %v\n", err)
				}
			}
		}
	}()
}

// finishProxyListen distinguishes SIGHUP (exit 75) from
// SIGINT/SIGTERM (exit 0) after the proxy server returns.
// Extracted from runProxyListen so the parent stays under
// funlen as the v1.15 chunk-5 SIGHUP path adds plumbing.
func finishProxyListen(cmd *cobra.Command, hupCh <-chan os.Signal) error {
	// If SIGHUP fired, signal the supervisor that this is a
	// reload (exit 75 / EX_TEMPFAIL). systemd's Restart=always
	// + RestartPreventExitStatus= can distinguish this from a
	// real crash; runit / s6 just restart unconditionally.
	select {
	case <-hupCh:
		cmd.Printf("proxy: stopping for SIGHUP reload (exit %d — supervisor should restart)\n", core.ExitTempFail)
		return fail(core.ExitTempFail, errReloadRequested)
	default:
	}
	cmd.Printf("proxy: stopped cleanly\n")
	return nil
}

// errReloadRequested is the sentinel returned when SIGHUP triggers
// a graceful exit. The exit-code wrapper translates this into
// core.ExitTempFail (75) so supervisors can distinguish reload
// from crash.
var errReloadRequested = errors.New("proxy: SIGHUP reload requested (operator should restart with updated config)")

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
	if opts.reloadAllowFile && opts.allowFile == "" {
		return errors.New("--reload-allow-file requires --allow-file (the SIGUSR1 reload path re-reads the YAML)")
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
		TokenGeneration:      opts.tokenGeneration,
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
		Target:          opts.target,
		Allowed:         allowed,
		TokenGeneration: opts.tokenGeneration,
		Deriver:         rt.Vault,
		Auditor:         rt.Auditor,
		SessionConfirm:  c,
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
		Target:          opts.target,
		Allowed:         allowed,
		TokenGeneration: opts.tokenGeneration,
		Deriver:         rt.Vault,
		Auditor:         rt.Auditor,
		SessionConfirm:  c,
	}, nil
}

func buildModbusHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*modwrite.WriteGatedHandler, error) {
	allowed, err := buildModbusAllowlist(opts)
	if err != nil {
		return nil, err
	}
	return &modwrite.WriteGatedHandler{
		Target:          opts.target,
		Allowed:         allowed,
		TokenGeneration: opts.tokenGeneration,
		Deriver:         rt.Vault,
		Auditor:         rt.Auditor,
		SessionConfirm:  c,
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
		TokenGeneration:         opts.tokenGeneration,
		Deriver:                 rt.Vault,
		Auditor:                 rt.Auditor,
		SessionConfirm:          c,
	}, nil
}

func buildBACnetHandler(opts proxyListenOpts, rt *offensiveRuntime, c confirm.Confirm) (*bacwrite.WriteGatedHandler, error) {
	allowed, err := buildBACnetServiceList(opts.serviceChoices)
	if err != nil {
		return nil, err
	}
	parsed, err := parseBACnetProxyOpts(opts)
	if err != nil {
		return nil, err
	}
	return &bacwrite.WriteGatedHandler{
		Target:                       opts.target,
		Allowed:                      allowed,
		AllowedObjects:               parsed.objs,
		AllowedDeleteObjects:         parsed.delObjs,
		AllowedCreateObjects:         parsed.creObjs,
		AllowedCreateObjectInstances: parsed.creObjInst,
		AllowedReinitStates:          parsed.reiSts,
		AllowedDCCStates:             parsed.dccSts,
		AllowedLSOOperations:         parsed.lsoOps,
		AllowedLSOTargets:            parsed.lsoTargets,
		AllowedAtomicWriteFiles:      parsed.awfFiles,
		AllowedListElements:          parsed.listEls,
		TokenGeneration:              opts.tokenGeneration,
		Deriver:                      rt.Vault,
		Auditor:                      rt.Auditor,
		SessionConfirm:               c,
	}, nil
}

// buildBACnetServiceList parses --service-choice values into
// AllowedService entries. Extracted from buildBACnetHandler so
// the latter stays under the funlen threshold.
func buildBACnetServiceList(in []uint) ([]bacwrite.AllowedService, error) {
	out := make([]bacwrite.AllowedService, 0, len(in))
	for _, s := range in {
		sc, err := parseByteFlag("--service-choice", s)
		if err != nil {
			return nil, err
		}
		out = append(out, bacwrite.AllowedService{ServiceChoice: sc})
	}
	return out, nil
}

// parsedBACnetProxyOpts holds the parsed per-service-dimension
// allowlists for buildBACnetHandler. Pulled into its own struct
// so the parser helper can return them all without growing the
// signature past readability.
type parsedBACnetProxyOpts struct {
	objs       []bacwrite.AllowedObject
	delObjs    []bacwrite.AllowedDeleteObject
	creObjs    []bacwrite.AllowedCreateObject
	creObjInst []bacwrite.AllowedCreateObjectInstance
	reiSts     []bacwrite.AllowedReinitState
	dccSts     []bacwrite.AllowedDCCState
	lsoOps     []bacwrite.AllowedLSOOperation
	lsoTargets []bacwrite.AllowedLSOTarget
	awfFiles   []bacwrite.AllowedAtomicWriteFile
	listEls    []bacwrite.AllowedListElement
}

// parseBACnetProxyOpts parses every per-service-dimension flag
// from the proxy listen opts struct and returns them bundled.
// Extracted from buildBACnetHandler so the latter stays under
// the funlen threshold (v1.16 chunk 3 added the LSOTargets
// dimension which pushed it over).
func parseBACnetProxyOpts(opts proxyListenOpts) (parsedBACnetProxyOpts, error) {
	var p parsedBACnetProxyOpts
	var err error
	if p.objs, err = parseBACnetObjectFlags(opts.bacnetObjects); err != nil {
		return p, err
	}
	if p.delObjs, err = parseBACnetDeleteObjectFlags(opts.bacnetDeleteObjects); err != nil {
		return p, err
	}
	if p.creObjs, err = parseBACnetCreateObjectTypes(opts.bacnetCreateObjectTypes); err != nil {
		return p, err
	}
	if p.creObjInst, err = parseBACnetCreateObjectInstanceFlags(opts.bacnetCreateObjectInstances); err != nil {
		return p, err
	}
	if p.reiSts, err = parseBACnetReinitStates(opts.bacnetReinitStates); err != nil {
		return p, err
	}
	if p.dccSts, err = parseBACnetDCCStates(opts.bacnetDCCStates); err != nil {
		return p, err
	}
	if p.lsoOps, err = parseBACnetLSOOps(opts.bacnetLSOOps); err != nil {
		return p, err
	}
	if p.lsoTargets, err = parseBACnetLSOTargetFlags(opts.bacnetLSOTargets); err != nil {
		return p, err
	}
	if p.awfFiles, err = parseBACnetAWFFiles(opts.bacnetAWFFiles); err != nil {
		return p, err
	}
	if p.listEls, err = parseBACnetListElementFlags(opts.bacnetListElements); err != nil {
		return p, err
	}
	return p, nil
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
		TokenGeneration:       opts.tokenGeneration,
		// v1.15 chunk 1: passive observer for the CPE → ACS
		// TransferComplete RPC. Operators see the firmware-push
		// outcome alongside their dry-run authorisation in the
		// proxy log stream.
		OnTransferComplete: defaultTransferCompleteObserver(opts.target),
		Deriver:            rt.Vault,
		Auditor:            rt.Auditor,
		SessionConfirm:     c,
	}, nil
}

// defaultTransferCompleteObserver writes a structured stderr
// log line for each TransferComplete envelope seen by the
// CWMP gate. Format mirrors the existing ElSereno operator
// stream: TIMESTAMP level=info msg=cwmp_transfer_complete
// target=... outcome=... command_key=... fault_code=... ...
//
// v1.16 chunk 1 enrichment: when the gate resolves the prior
// Download authorisation that started this transfer, the log
// line carries `outcome=succeeded|failed` plus
// `download_url=` + `allowlist_sha256=` cross-references.
// When no matching authorisation is found,
// `outcome=orphan_complete|orphan_fault` and the cross-ref
// fields are empty — operators should alert on orphan rows.
//
// Lightweight on purpose — runs synchronously on the proxy
// request goroutine. Operators wanting structured ingest
// should pipe stderr through their existing zerolog/loki/etc.
// pipeline.
func defaultTransferCompleteObserver(target string) cwmpwrite.TransferCompleteObserver {
	return func(f cwmpwrite.TransferCompleteFields) {
		var (
			downloadURL string
			allowSHA256 string
			authoredAt  string
		)
		if f.Authorisation != nil {
			downloadURL = f.Authorisation.DownloadURL
			allowSHA256 = f.Authorisation.AllowlistSHA256
			authoredAt = f.Authorisation.AuthorisedAt.Format(time.RFC3339Nano)
		}
		fmt.Fprintf(os.Stderr,
			"%s level=info msg=cwmp_transfer_complete target=%q outcome=%s command_key=%q fault_code=%q fault_string=%q start=%q complete=%q download_url=%q allowlist_sha256=%q authorised_at=%q\n",
			time.Now().UTC().Format(time.RFC3339Nano),
			target, f.Outcome(), f.CommandKey, f.FaultCode, f.FaultString,
			f.StartTime, f.CompleteTime,
			downloadURL, allowSHA256, authoredAt,
		)
	}
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
