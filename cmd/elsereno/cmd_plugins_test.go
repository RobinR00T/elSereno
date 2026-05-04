package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"local/elsereno/internal/core"
)

// TestBuildPluginsByPort_ColocatedPort — the canonical
// shared-port case (mms + s7 both on 102). Pin both names
// in alphabetical order so the JSON output stays stable.
func TestBuildPluginsByPort_ColocatedPort(t *testing.T) {
	in := []core.Plugin{
		{PluginMetadata: core.PluginMetadata{Name: "mms", DefaultPort: 102}},
		{PluginMetadata: core.PluginMetadata{Name: "s7", DefaultPort: 102}},
		{PluginMetadata: core.PluginMetadata{Name: "modbus", DefaultPort: 502}},
	}
	got := buildPluginsByPort(in)
	if len(got[102]) != 2 {
		t.Fatalf("port 102 plugins = %v, want 2", got[102])
	}
	if got[102][0] != "mms" || got[102][1] != "s7" {
		t.Errorf("port 102 plugins = %v, want [mms s7]", got[102])
	}
	if got[502][0] != "modbus" {
		t.Errorf("port 502 plugins = %v, want [modbus]", got[502])
	}
}

// TestBuildPluginsByPort_SkipsZeroPort — atmodem has no
// well-known port (DefaultPort: 0); it must NOT appear in
// the output.
func TestBuildPluginsByPort_SkipsZeroPort(t *testing.T) {
	in := []core.Plugin{
		{PluginMetadata: core.PluginMetadata{Name: "atmodem", DefaultPort: 0}},
		{PluginMetadata: core.PluginMetadata{Name: "modbus", DefaultPort: 502}},
	}
	got := buildPluginsByPort(in)
	if _, exists := got[0]; exists {
		t.Errorf("port 0 entry exists; expected zero-port plugins to be skipped")
	}
	if len(got) != 1 {
		t.Errorf("map size = %d, want 1 (modbus only)", len(got))
	}
}

// TestPluginsPortsCmd_TextOutput drives the cobra verb +
// asserts that a known port appears in the rendered output.
// The exact set of ports depends on which plugins are linked
// in this build (default-build linking; offensive plugins
// don't add new ports).
func TestPluginsPortsCmd_TextOutput(t *testing.T) {
	cmd := newPluginsPortsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(t.Context())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	body := out.String()
	// modbus → 502 is one of the most stable port assignments
	// in the registry; pin it.
	if !strings.Contains(body, "502") || !strings.Contains(body, "modbus") {
		t.Errorf("expected '502' + 'modbus' in output:\n%s", body)
	}
}

// TestPluginsPortsCmd_JSONOutput pins the JSON shape: an
// object keyed by port (as JSON string), values are arrays
// of plugin names.
func TestPluginsPortsCmd_JSONOutput(t *testing.T) {
	cmd := newPluginsPortsCmd()
	cmd.SetArgs([]string{"--json"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(t.Context())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var got map[string][]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\noutput:\n%s", err, out.String())
	}
	if len(got["502"]) == 0 || got["502"][0] != "modbus" {
		t.Errorf("port 502 = %v, want [modbus]", got["502"])
	}
	// Port 102 should list mms + s7 (alphabetical).
	if len(got["102"]) >= 2 {
		if got["102"][0] != "mms" || got["102"][1] != "s7" {
			t.Errorf("port 102 = %v, want [mms s7] alphabetical",
				got["102"])
		}
	}
}
