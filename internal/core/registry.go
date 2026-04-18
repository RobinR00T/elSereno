package core

import (
	"sort"
	"sync"
)

// Register is called from plugin init() to announce a protocol. It is
// safe for concurrent use; panics on duplicate registration to surface
// misconfiguration at startup rather than at runtime.
func Register(p Plugin) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, dup := registry.plugins[p.Name]; dup {
		panic("core: duplicate plugin registration for " + p.Name)
	}
	if registry.plugins == nil {
		registry.plugins = make(map[string]Plugin)
	}
	registry.plugins[p.Name] = p
}

// RegisteredPlugins returns a copy of the current registry sorted by
// name. The result is safe to hand out to callers (no aliasing).
func RegisteredPlugins() []Plugin {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	out := make([]Plugin, 0, len(registry.plugins))
	for _, p := range registry.plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}
