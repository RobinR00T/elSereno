package main

import (
	"bytes"
	"strings"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/standards"
)

func TestStandardsCmdRuns(t *testing.T) {
	t.Parallel()
	cmd := newStandardsCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--protocol", "s7-exposure"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("standards: %v", err)
	}
	if !strings.Contains(buf.String(), "Table 16") {
		t.Errorf("expected a Table 16 reference for s7-exposure:\n%s", buf.String())
	}
}

// TestStandardsMappingMatchesRegisteredPlugins guards against a dead map
// entry: every protocol with a standards mapping must be a registered
// plugin, or the mapping would never fire on a real finding.
func TestStandardsMappingMatchesRegisteredPlugins(t *testing.T) {
	t.Parallel()
	registered := map[string]bool{}
	for _, p := range core.RegisteredPlugins() {
		registered[p.Name] = true
	}
	for _, proto := range standards.Protocols() {
		if !registered[proto] {
			t.Errorf("standards maps %q but no plugin with that name is registered", proto)
		}
	}
}
