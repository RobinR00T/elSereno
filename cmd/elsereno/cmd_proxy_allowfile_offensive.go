//go:build offensive

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Plugin name constants shared across the allow-file loader +
// the buildGatedHandler dispatcher. goconst flagged the
// repeated string literals.
const (
	pluginNameSIP     = "sip"
	pluginNameIAX2    = "iax2"
	pluginNamePBXHTTP = "pbxhttp"
	pluginNameModbus  = "modbus"
	pluginNameOPCUA   = "opcua"
	pluginNameBACnet  = "bacnet"
	pluginNameCWMP    = "cwmp"
)

// proxyAllowFile is the YAML schema for --allow-file. Every
// plugin has its own required field set; unused fields are
// ignored. Keeping every plugin's allowlist in one struct
// means the CLI only has to invoke one unmarshaller regardless
// of which plugin the operator selected.
//
// Example (sip):
//
//	plugin: sip
//	target: pbx.example.com:5060
//	methods:
//	  - INVITE
//	  - REGISTER
//
// Example (pbxhttp):
//
//	plugin: pbxhttp
//	target: pbx.example.com:443
//	allow:
//	  - "POST:/admin/config.php"
//	  - "DELETE:/admin/user/42"
//
// Example (modbus):
//
//	plugin: modbus
//	target: plc.example.com:502
//	functions: [6, 16]
//
// When --allow-file is used, the --plugin + --target + per-
// plugin allowlist flags are derived from the file. If any of
// those flags are ALSO supplied on the command line, the file
// wins (with a printed warning).
// proxyModbusWrite is the YAML-structured form of a Modbus
// AllowedWrite entry for the modbus per-write allowlist (v1.12+).
// When non-nil, writes: entries are merged with any legacy
// `functions:` list so the loader keeps v1.9 tokens stable.
//
// Example:
//
//	writes:
//	  - unit: 1
//	    fc: 6
//	    start: 100
//	    end: 200
//	  - unit: 2
//	    fc: 16
//	  - fc: 5  # any unit, any address
//
// Each field is optional: `unit: 0` (or omitted) matches any
// unit; start+end both omitted match any address.
type proxyModbusWrite struct {
	Unit  uint8  `yaml:"unit,omitempty"`
	FC    uint8  `yaml:"fc"`
	Start uint16 `yaml:"start,omitempty"`
	End   uint16 `yaml:"end,omitempty"`
}

// proxyCWMPFirmware is the YAML-structured form of a CWMP
// AllowedFirmware entry (v1.12 chunk 10). Per-image allowlist
// for the Download RPC.
//
//	url:    "https://acs.example.com/firmware/router-1.2.3.bin"
//	sha256: "<64 hex chars>"   # optional metadata
//
// SHA256 is for downstream verification (TR-069 doesn't carry
// it in Download); the gate enforces URL only.
type proxyCWMPFirmware struct {
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256,omitempty"`
}

// proxyBACnetObject is the YAML-structured form of a BACnet
// AllowedObject (v1.12 chunk 7). Three 32-bit fields:
//
//	type:     BACnetObjectType (0..1023)
//	instance: Object instance number (0..4_194_303)
//	property: BACnetPropertyIdentifier enum
//
// Example:
//
//	objects:
//	  - type: 0          # AnalogInput
//	    instance: 42
//	    property: 85     # PresentValue
//	  - type: 2          # BinaryOutput
//	    instance: 3
//	    property: 85
//
// Operator allowlists specific WriteProperty targets; everything
// else refuses even when service 15 is in the service-choice
// allowlist.
type proxyBACnetObject struct {
	Type     uint16 `yaml:"type"`
	Instance uint32 `yaml:"instance"`
	Property uint32 `yaml:"property"`
}

// proxyBACnetDeleteObject is the YAML form of an
// AllowedDeleteObject (v1.13 chunk 7). Two fields only —
// PropertyID doesn't apply to object-level deletion.
//
// Example:
//
//	delete_objects:
//	  - type: 2          # BinaryOutput
//	    instance: 99
//	  - type: 19         # MultiStateValue
//	    instance: 7
//
// Operator allowlists specific DeleteObject targets. v1.13
// chunks 7-13 closed every BACnet mutating service at natural
// granularity; per-instance Create + per-object LSO are
// v1.16+ tightenings if anyone asks.
type proxyBACnetDeleteObject struct {
	Type     uint16 `yaml:"type"`
	Instance uint32 `yaml:"instance"`
}

// proxyBACnetListElement is the YAML form of an
// AllowedListElement (v1.13 chunk 13). Same shape as
// proxyBACnetObject (Type + Instance + Property) but applies
// only to AddListElement (svc 8) + RemoveListElement (svc 9).
//
// Example:
//
//	list_elements:
//	  - type: 15        # NotificationClass
//	    instance: 1
//	    property: 102   # recipient_list
//	  - type: 17        # Schedule
//	    instance: 3
//	    property: 38    # exception_schedule
//
// Operator allowlists specific list-typed properties that
// may be appended-to (svc 8) or removed-from (svc 9).
type proxyBACnetListElement struct {
	Type     uint16 `yaml:"type"`
	Instance uint32 `yaml:"instance"`
	Property uint32 `yaml:"property"`
}

// proxyBACnetCreateObject is the YAML form of an
// AllowedCreateObject (v1.13 chunk 8). One field — Type only.
// Instance is intentionally absent: the most common
// CreateObject form has the device pick the instance, and the
// typical BAS use-case is "operator may create objects of
// these types" (allowlist by type, not by exact tuple).
//
// Example:
//
//	create_object_types:
//	  - type: 17        # Schedule
//	  - type: 19        # MultiStateValue
//
// When the [1] objectIdentifier choice form encodes an instance,
// the v1.13 gate still matches by type only (instance is ignored).
// v1.16+ adds a parallel `create_object_instances:` list — see
// proxyBACnetCreateObjectInstance — for per-(type, instance)
// scoping when the ACS uses CHOICE [1].
type proxyBACnetCreateObject struct {
	Type uint16 `yaml:"type"`
}

// proxyBACnetCreateObjectInstance is the v1.16 chunk-2
// refinement of proxyBACnetCreateObject: scopes a CreateObject
// confirmed-request (service 10) to a specific
// (ObjectType, ObjectInstance) tuple. Round-tripped from
// `--create-object-instance type=N;instance=M` CLI flags.
//
// Example:
//
//	create_object_instances:
//	  - type: 17        # Schedule
//	    instance: 42
//	  - type: 19        # MultiStateValue
//	    instance: 7
//
// See offensive/write/bacnet.AllowedCreateObjectInstance for
// the matching-precedence rules (per-instance match wins; falls
// back to per-type list).
type proxyBACnetCreateObjectInstance struct {
	Type     uint16 `yaml:"type"`
	Instance uint32 `yaml:"instance"`
}

// proxyBACnetLSOTarget is the v1.16 chunk-3 YAML form of an
// AllowedLSOTarget: scopes a LifeSafetyOperation request
// (service 27) to a specific (Operation, ObjectType,
// ObjectInstance) tuple. Round-tripped from
// `--lso-target op=N;type=N;instance=N` CLI flags.
//
// Example:
//
//	lso_targets:
//	  - op: 7           # Unsilence
//	    type: 21        # LifeSafetyPoint
//	    instance: 3
//	  - op: 4           # Reset
//	    type: 21
//	    instance: 3
//
// See offensive/write/bacnet.AllowedLSOTarget for the
// matching-precedence rules (per-target match wins; falls back
// to per-operation list).
type proxyBACnetLSOTarget struct {
	Op       uint8  `yaml:"op"`
	Type     uint16 `yaml:"type"`
	Instance uint32 `yaml:"instance"`
}

// proxyCallMethod is the YAML-structured form of an OPC UA
// AllowedCallMethod for per-session CallRequest gating (v1.12+).
// Both fields are canonical-string NodeIds (ns=N;i=M | s= |
// g= | b=). Emitted + loaded verbatim — the loader pushes them
// back as `--call-method object=…;method=…` strings on
// proxyListenOpts.
//
// Example:
//
//	call_methods:
//	  - object: "ns=2;i=100"
//	    method: "ns=2;i=101"
//	  - object: "ns=3;s=DeviceFolder"
//	    method: "ns=3;s=Restart"
type proxyCallMethod struct {
	Object string `yaml:"object"`
	Method string `yaml:"method"`
}

// proxyNodeID is the YAML-structured form of an OPC UA NodeID
// for the opcua per-node allowlist. Two shapes supported:
//
//	Numeric (v1.9+):
//	  - namespace: 2
//	    identifier: 42
//
//	Canonical (v1.12+):
//	  - canonical: "ns=2;s=Temperature"
//	  - canonical: "ns=1;g=6B29FC40CA471067B31D00DD010662DA"
//	  - canonical: "ns=3;b=DEADBEEF"
//
// Exactly one shape should be populated per entry. When
// `canonical` is non-empty it wins; otherwise namespace +
// identifier are used. The loader emits both forms as
// `--node-id` strings for proxyListenOpts.
type proxyNodeID struct {
	Namespace  uint16 `yaml:"namespace,omitempty"`
	Identifier uint32 `yaml:"identifier,omitempty"`
	Canonical  string `yaml:"canonical,omitempty"`
}

type proxyAllowFile struct {
	Plugin string `yaml:"plugin"`
	Target string `yaml:"target"`

	// Per-plugin allowlist fields (only the one matching Plugin
	// is consulted). `omitempty` keeps the emitted YAML focused
	// on the fields relevant to this plugin — a sip dry-run's
	// emit-allow-file shouldn't drop empty `subclasses: []` or
	// `functions: []` keys into the file.
	Methods               []string                          `yaml:"methods,omitempty"`                 // sip
	ToPrefixes            []string                          `yaml:"to_prefixes,omitempty"`             // sip (v1.9+) — INVITE destination allowlist
	AORs                  []string                          `yaml:"aors,omitempty"`                    // sip (v1.10+) — REGISTER AOR allowlist
	FromDomains           []string                          `yaml:"from_domains,omitempty"`            // sip (v1.12+) — From-header domain allowlist
	Subclasses            []string                          `yaml:"subclasses,omitempty"`              // iax2
	Allow                 []string                          `yaml:"allow,omitempty"`                   // pbxhttp
	Functions             []uint                            `yaml:"functions,omitempty"`               // modbus (legacy: FC-only, any unit/addr)
	Writes                []proxyModbusWrite                `yaml:"writes,omitempty"`                  // modbus (v1.12+: structured unit+fc+start+end)
	Services              []uint                            `yaml:"services,omitempty"`                // opcua
	NodeIDs               []proxyNodeID                     `yaml:"node_ids,omitempty"`                // opcua (v1.9+)
	CallMethods           []proxyCallMethod                 `yaml:"call_methods,omitempty"`            // opcua (v1.12+) — per-CallMethod (object,method) pairs
	ServiceChoices        []uint                            `yaml:"service_choices,omitempty"`         // bacnet
	Objects               []proxyBACnetObject               `yaml:"objects,omitempty"`                 // bacnet (v1.12+) — per-object WriteProperty allowlist
	DeleteObjects         []proxyBACnetDeleteObject         `yaml:"delete_objects,omitempty"`          // bacnet (v1.13+) — per-target DeleteObject allowlist
	CreateObjectTypes     []proxyBACnetCreateObject         `yaml:"create_object_types,omitempty"`     // bacnet (v1.13+) — per-type CreateObject allowlist
	CreateObjectInstances []proxyBACnetCreateObjectInstance `yaml:"create_object_instances,omitempty"` // bacnet (v1.16+) — per-(type, instance) CreateObject allowlist
	ReinitStates          []uint8                           `yaml:"reinit_states,omitempty"`           // bacnet (v1.13+) — per-state ReinitializeDevice allowlist
	DCCStates             []uint8                           `yaml:"dcc_states,omitempty"`              // bacnet (v1.13+) — per-state DeviceCommControl allowlist
	LSOOps                []uint8                           `yaml:"lso_ops,omitempty"`                 // bacnet (v1.13+) — per-operation LifeSafetyOperation allowlist
	LSOTargets            []proxyBACnetLSOTarget            `yaml:"lso_targets,omitempty"`             // bacnet (v1.16+) — per-(operation, type, instance) LifeSafetyOperation allowlist
	AWFFiles              []uint32                          `yaml:"awf_files,omitempty"`               // bacnet (v1.13+) — per-File-instance AtomicWriteFile allowlist
	ListElements          []proxyBACnetListElement          `yaml:"list_elements,omitempty"`           // bacnet (v1.13+) — per-(object, property) Add/RemoveListElement allowlist
	RPCs                  []string                          `yaml:"rpcs,omitempty"`                    // cwmp (v1.11+) — SOAP RPC allowlist
	ParamPrefixes         []string                          `yaml:"param_prefixes,omitempty"`          // cwmp (v1.12+) — parameter-path allowlist for Set* RPCs
	Firmware              []proxyCWMPFirmware               `yaml:"firmware,omitempty"`                // cwmp (v1.12+) — per-image allowlist for Download
}

// loadAllowFile reads + parses an allow-file and merges its
// values into opts. Returns a non-nil error when the file is
// unreadable, malformed, or missing a required field for the
// declared plugin.
func loadAllowFile(path string, opts *proxyListenOpts) error {
	raw, err := os.ReadFile(path) //nolint:gosec // G304 — path is operator-supplied; directory traversal is their privilege on their own machine.
	if err != nil {
		return fmt.Errorf("--allow-file %s: %w", path, err)
	}
	var af proxyAllowFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&af); err != nil {
		return fmt.Errorf("--allow-file %s: parse: %w", path, err)
	}
	if af.Plugin == "" {
		return errors.New("--allow-file: missing required field `plugin`")
	}
	if af.Target == "" {
		return errors.New("--allow-file: missing required field `target`")
	}

	opts.plugin = af.Plugin
	opts.target = af.Target
	switch strings.ToLower(af.Plugin) {
	case pluginNameSIP:
		opts.methods = af.Methods
		opts.toPrefixes = af.ToPrefixes
		opts.aors = af.AORs
		opts.fromDomains = af.FromDomains
	case pluginNameIAX2:
		opts.subclasses = af.Subclasses
	case pluginNamePBXHTTP:
		opts.allowEntries = af.Allow
	case pluginNameModbus:
		applyModbusAllowFile(&af, opts)
	case pluginNameOPCUA:
		applyOPCUAAllowFile(&af, opts)
	case pluginNameBACnet:
		applyBACnetAllowFile(&af, opts)
	case pluginNameCWMP:
		applyCWMPAllowFile(&af, opts)
	default:
		return fmt.Errorf("--allow-file: unsupported plugin %q", af.Plugin)
	}
	return nil
}

// applyBACnetAllowFile populates proxyListenOpts from the bacnet
// plugin's YAML. Extracted so loadAllowFile stays under funlen.
// Walks every BACnet allowlist field (services, per-property
// objects, per-target deletes, per-type creates, per-state
// reinitializeDevice, per-state DeviceCommControl, per-operation
// LifeSafetyOperation).
func applyBACnetAllowFile(af *proxyAllowFile, opts *proxyListenOpts) {
	opts.serviceChoices = af.ServiceChoices
	for _, o := range af.Objects {
		opts.bacnetObjects = append(opts.bacnetObjects,
			fmt.Sprintf("type=%d;instance=%d;property=%d",
				o.Type, o.Instance, o.Property))
	}
	for _, d := range af.DeleteObjects {
		opts.bacnetDeleteObjects = append(opts.bacnetDeleteObjects,
			fmt.Sprintf("type=%d;instance=%d", d.Type, d.Instance))
	}
	for _, c := range af.CreateObjectTypes {
		opts.bacnetCreateObjectTypes = append(opts.bacnetCreateObjectTypes, uint(c.Type))
	}
	for _, c := range af.CreateObjectInstances {
		opts.bacnetCreateObjectInstances = append(opts.bacnetCreateObjectInstances,
			fmt.Sprintf("type=%d;instance=%d", c.Type, c.Instance))
	}
	for _, s := range af.ReinitStates {
		opts.bacnetReinitStates = append(opts.bacnetReinitStates, uint(s))
	}
	for _, s := range af.DCCStates {
		opts.bacnetDCCStates = append(opts.bacnetDCCStates, uint(s))
	}
	for _, o := range af.LSOOps {
		opts.bacnetLSOOps = append(opts.bacnetLSOOps, uint(o))
	}
	for _, t := range af.LSOTargets {
		opts.bacnetLSOTargets = append(opts.bacnetLSOTargets,
			fmt.Sprintf("op=%d;type=%d;instance=%d", t.Op, t.Type, t.Instance))
	}
	for _, f := range af.AWFFiles {
		opts.bacnetAWFFiles = append(opts.bacnetAWFFiles, uint(f))
	}
	for _, e := range af.ListElements {
		opts.bacnetListElements = append(opts.bacnetListElements,
			fmt.Sprintf("type=%d;instance=%d;property=%d",
				e.Type, e.Instance, e.Property))
	}
}

// applyCWMPAllowFile populates proxyListenOpts from the cwmp
// plugin's YAML. Extracted so loadAllowFile stays under funlen.
func applyCWMPAllowFile(af *proxyAllowFile, opts *proxyListenOpts) {
	opts.rpcs = af.RPCs
	opts.paramPrefixes = af.ParamPrefixes
	for _, f := range af.Firmware {
		entry := "url=" + f.URL
		if f.SHA256 != "" {
			entry += ";sha256=" + f.SHA256
		}
		opts.cwmpFirmware = append(opts.cwmpFirmware, entry)
	}
}

// applyModbusAllowFile populates proxyListenOpts from the modbus
// plugin's YAML. Merges the legacy `functions:` list (v1.9+, FC-
// only, any unit / any address) with the v1.12+ structured
// `writes:` entries. Both produce uniform modbusWrites entries;
// the handler does not distinguish between them.
func applyModbusAllowFile(af *proxyAllowFile, opts *proxyListenOpts) {
	opts.functions = af.Functions
	if len(af.Writes) == 0 {
		return
	}
	opts.modbusWritesYAML = make([]proxyModbusWrite, 0, len(af.Writes))
	opts.modbusWritesYAML = append(opts.modbusWritesYAML, af.Writes...)
}

// applyOPCUAAllowFile populates proxyListenOpts from the opcua
// plugin's YAML. Handles both v1.9 numeric (namespace+identifier)
// and v1.12 canonical entries. Extracted from loadAllowFile to
// keep that function under the funlen threshold.
func applyOPCUAAllowFile(af *proxyAllowFile, opts *proxyListenOpts) {
	opts.services = af.Services
	for _, n := range af.NodeIDs {
		if n.Canonical != "" {
			// Canonical string is already the CLI `ns=N;<k>=<v>`
			// form; keep verbatim.
			opts.nodeIDs = append(opts.nodeIDs, n.Canonical)
			continue
		}
		opts.nodeIDs = append(opts.nodeIDs,
			fmt.Sprintf("ns=%d;i=%d", n.Namespace, n.Identifier))
	}
	for _, cm := range af.CallMethods {
		opts.callMethods = append(opts.callMethods,
			fmt.Sprintf("object=%s;method=%s", cm.Object, cm.Method))
	}
}
