//go:build offensive

package main

import (
	"testing"

	"local/elsereno/offensive/confirm"
	iaxwrite "local/elsereno/offensive/write/iax2"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	sipwrite "local/elsereno/offensive/write/sip"
)

// ---- buildGatedHandler plugin dispatch ------------------------

func TestBuildGatedHandler_SIP(t *testing.T) {
	// runtime nil is fine — buildGatedHandler only reads
	// rt.Vault + rt.Auditor when the handler is actually
	// invoked.
	opts := proxyListenOpts{
		plugin:  "sip",
		target:  "pbx.test:5060",
		methods: []string{"INVITE", "REGISTER"},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*sipwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *sipwrite.WriteGatedHandler, got %T", h)
	}
	if concrete.Target != "pbx.test:5060" {
		t.Errorf("Target = %q, want pbx.test:5060", concrete.Target)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_IAX2(t *testing.T) {
	opts := proxyListenOpts{
		plugin:     "iax2",
		target:     "pbx.test:4569",
		subclasses: []string{"NEW", "REGREQ"},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*iaxwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *iaxwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_IAX2UnknownSubclass(t *testing.T) {
	// Unknown subclass should bubble up an error — better UX than
	// silently accepting an always-safe subclass as "authorised".
	opts := proxyListenOpts{
		plugin:     "iax2",
		target:     "pbx.test:4569",
		subclasses: []string{"HANGUP"}, // always-safe, not valid as an allowlist entry
	}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
		t.Fatal("expected error for invalid subclass")
	}
}

func TestBuildGatedHandler_PBXHTTP(t *testing.T) {
	opts := proxyListenOpts{
		plugin:       "pbxhttp",
		target:       "pbx.test:443",
		allowEntries: []string{"POST:/admin/config.php", "DELETE:/admin/user/42"},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*pbxwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *pbxwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_PBXHTTPMalformedAllow(t *testing.T) {
	opts := proxyListenOpts{
		plugin:       "pbxhttp",
		target:       "pbx.test:443",
		allowEntries: []string{"POST"},
	}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
		t.Fatal("expected error for malformed --allow entry")
	}
}

func TestBuildGatedHandler_UnknownPlugin(t *testing.T) {
	for _, plugin := range []string{"", "modbus", "opcua", "bacnet", "SIP2"} {
		opts := proxyListenOpts{plugin: plugin, target: "host:1"}
		rt := &offensiveRuntime{}
		if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
			t.Errorf("--plugin %q: expected error, got none", plugin)
		}
	}
}

func TestBuildGatedHandler_CaseInsensitivePlugin(t *testing.T) {
	// The plugin switch lowercases its key.
	opts := proxyListenOpts{plugin: "SIP", target: "h:1", methods: []string{"OPTIONS"}}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err != nil {
		t.Fatalf("upper-case --plugin SIP should work: %v", err)
	}
}
