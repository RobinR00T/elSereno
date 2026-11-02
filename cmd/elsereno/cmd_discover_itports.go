package main

import (
	"sort"

	"local/elsereno/internal/exposure"
)

// catalogueITPorts returns the TCP IT rows of the port catalogue as
// discover entries, named by their catalogue protocol (rdp, smb, ...).
func catalogueITPorts() []pluginPort {
	var out []pluginPort
	for _, e := range exposure.Ports() {
		if e.Transport != exposure.TransportTCP || e.Category == exposure.CategoryOT {
			continue
		}
		out = append(out, pluginPort{Port: e.Port, PluginID: e.Protocol, Category: string(e.Category)})
	}
	return out
}

// categoryForPort returns the catalogue category of an --it-ports entry
// on port, or "" when only plugins claim it.
func categoryForPort(ports []pluginPort, port int) string {
	for _, p := range ports {
		if p.Port == port && p.Category != "" {
			return p.Category
		}
	}
	return ""
}

// uniquePorts returns each port once, ascending, so a port claimed by
// several plugins (5007: slmp and melsoft; 102: s7 and mms) or by a
// plugin and the catalogue (80, 443, 1883) is dialled once per host and
// its hit carries every claimant as a hint (PITF-112).
func uniquePorts(ports []pluginPort) []pluginPort {
	seen := map[int]bool{}
	out := make([]pluginPort, 0, len(ports))
	for _, p := range ports {
		if !seen[p.Port] {
			seen[p.Port] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}
