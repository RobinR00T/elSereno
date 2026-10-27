package main

import "testing"

func TestCatalogueITPorts_NoOTAndHasManagement(t *testing.T) {
	got := map[int]string{}
	for _, p := range catalogueITPorts() {
		if p.Category == "ot" || p.Category == "" {
			t.Errorf("port %d: category %q", p.Port, p.Category)
		}
		got[p.Port] = p.PluginID
	}
	for port, name := range map[int]string{22: "ssh", 445: "smb", 1433: "mssql", 3389: "rdp", 5900: "vnc", 443: "https"} {
		if got[port] != name {
			t.Errorf("port %d = %q, want %q", port, got[port], name)
		}
	}
	if _, ok := got[502]; ok {
		t.Error("an OT port leaked into the IT sweep")
	}
}

func TestUniquePortsAndCategory(t *testing.T) {
	ports := []pluginPort{{Port: 102, PluginID: "s7"}, {Port: 102, PluginID: "mms"}, {Port: 22, PluginID: "ssh", Category: "it-management"}}
	u := uniquePorts(ports)
	if len(u) != 2 || u[0].Port != 22 || u[1].Port != 102 {
		t.Fatalf("uniquePorts = %+v", u)
	}
	if categoryForPort(ports, 22) != "it-management" || categoryForPort(ports, 102) != "" {
		t.Error("categoryForPort")
	}
	if h := pluginsForPort(ports, 102); len(h) != 2 {
		t.Errorf("hints for 102 = %v", h)
	}
}
