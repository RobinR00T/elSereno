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
	Methods        []string           `yaml:"methods,omitempty"`         // sip
	ToPrefixes     []string           `yaml:"to_prefixes,omitempty"`     // sip (v1.9+) — INVITE destination allowlist
	AORs           []string           `yaml:"aors,omitempty"`            // sip (v1.10+) — REGISTER AOR allowlist
	Subclasses     []string           `yaml:"subclasses,omitempty"`      // iax2
	Allow          []string           `yaml:"allow,omitempty"`           // pbxhttp
	Functions      []uint             `yaml:"functions,omitempty"`       // modbus (legacy: FC-only, any unit/addr)
	Writes         []proxyModbusWrite `yaml:"writes,omitempty"`          // modbus (v1.12+: structured unit+fc+start+end)
	Services       []uint             `yaml:"services,omitempty"`        // opcua
	NodeIDs        []proxyNodeID      `yaml:"node_ids,omitempty"`        // opcua (v1.9+)
	ServiceChoices []uint             `yaml:"service_choices,omitempty"` // bacnet
	RPCs           []string           `yaml:"rpcs,omitempty"`            // cwmp (v1.11+) — SOAP RPC allowlist
	ParamPrefixes  []string           `yaml:"param_prefixes,omitempty"`  // cwmp (v1.12+) — parameter-path allowlist for Set* RPCs
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
	case pluginNameIAX2:
		opts.subclasses = af.Subclasses
	case pluginNamePBXHTTP:
		opts.allowEntries = af.Allow
	case pluginNameModbus:
		applyModbusAllowFile(&af, opts)
	case pluginNameOPCUA:
		applyOPCUAAllowFile(&af, opts)
	case pluginNameBACnet:
		opts.serviceChoices = af.ServiceChoices
	case pluginNameCWMP:
		opts.rpcs = af.RPCs
		opts.paramPrefixes = af.ParamPrefixes
	default:
		return fmt.Errorf("--allow-file: unsupported plugin %q", af.Plugin)
	}
	return nil
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
	if len(af.NodeIDs) == 0 {
		return
	}
	opts.nodeIDs = make([]string, 0, len(af.NodeIDs))
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
}
