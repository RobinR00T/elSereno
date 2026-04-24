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
// proxyNodeID is the YAML-structured form of an OPC UA NodeID
// for the opcua per-node allowlist (v1.9+). Loader translates
// it to the CLI `ns=N;i=M` string form used by proxyListenOpts.
type proxyNodeID struct {
	Namespace  uint16 `yaml:"namespace"`
	Identifier uint32 `yaml:"identifier"`
}

type proxyAllowFile struct {
	Plugin string `yaml:"plugin"`
	Target string `yaml:"target"`

	// Per-plugin allowlist fields (only the one matching Plugin
	// is consulted). `omitempty` keeps the emitted YAML focused
	// on the fields relevant to this plugin — a sip dry-run's
	// emit-allow-file shouldn't drop empty `subclasses: []` or
	// `functions: []` keys into the file.
	Methods        []string      `yaml:"methods,omitempty"`         // sip
	Subclasses     []string      `yaml:"subclasses,omitempty"`      // iax2
	Allow          []string      `yaml:"allow,omitempty"`           // pbxhttp
	Functions      []uint        `yaml:"functions,omitempty"`       // modbus
	Services       []uint        `yaml:"services,omitempty"`        // opcua
	NodeIDs        []proxyNodeID `yaml:"node_ids,omitempty"`        // opcua (v1.9+)
	ServiceChoices []uint        `yaml:"service_choices,omitempty"` // bacnet
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
	case pluginNameIAX2:
		opts.subclasses = af.Subclasses
	case pluginNamePBXHTTP:
		opts.allowEntries = af.Allow
	case pluginNameModbus:
		opts.functions = af.Functions
	case pluginNameOPCUA:
		opts.services = af.Services
		if len(af.NodeIDs) > 0 {
			opts.nodeIDs = make([]string, 0, len(af.NodeIDs))
			for _, n := range af.NodeIDs {
				opts.nodeIDs = append(opts.nodeIDs,
					fmt.Sprintf("ns=%d;i=%d", n.Namespace, n.Identifier))
			}
		}
	case pluginNameBACnet:
		opts.serviceChoices = af.ServiceChoices
	default:
		return fmt.Errorf("--allow-file: unsupported plugin %q", af.Plugin)
	}
	return nil
}
