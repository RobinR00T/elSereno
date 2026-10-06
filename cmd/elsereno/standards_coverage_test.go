package main

import (
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/standards"
)

// standardsExempt lists registered plugins that deliberately carry no
// standards mapping, each with the reason. Everything else must be mapped.
var standardsExempt = map[string]string{
	"banner": "generic banner/dictionary grabber: no protocol-level weakness to claim",
}

// TestEveryRegisteredPluginHasStandardsMapping guards against a new plugin
// silently shipping without NIST SP 800-82 traceability: ForProtocol returns
// nil for an unmapped protocol (by design, to never over-claim), so a missing
// entry drops the references from every output surface without any error.
// The 2026-10-07 audit found exactly that for melsoft.
func TestEveryRegisteredPluginHasStandardsMapping(t *testing.T) {
	for _, p := range core.RegisteredPlugins() {
		if _, ok := standardsExempt[p.Name]; ok {
			continue
		}
		if standards.ForProtocol(p.Name) == nil {
			t.Errorf("plugin %q is registered but has no internal/standards mapping: add it to protocolRefs or to standardsExempt with a reason", p.Name)
		}
	}
	for name := range standardsExempt {
		if standards.ForProtocol(name) != nil {
			t.Errorf("plugin %q is exempt but now has a mapping: drop the exemption", name)
		}
	}
}
