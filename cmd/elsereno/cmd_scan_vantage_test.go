package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
)

func TestValidVantage(t *testing.T) {
	for v, want := range map[string]bool{
		"": true, "it-office-vlan": true, "dmz:fw2_a.1": true,
		"bad label": false, "x\n": false, strings.Repeat("a", 65): false, "ü": false,
	} {
		if validVantage(v) != want {
			t.Errorf("validVantage(%q) != %v", v, want)
		}
	}
}

func TestScanOutputCarriesVantage(t *testing.T) {
	f := core.Finding{ID: "f1", Protocol: "modbus", Severity: "high", Score: 70, CreatedAt: time.Unix(0, 0)}
	tgt := core.Target{Address: netip.MustParseAddr("192.0.2.5"), Port: 502}
	for _, format := range []string{"ndjson", "stix"} {
		var out bytes.Buffer
		write, cleanup, err := scanOutput(&out, format, "it-office-vlan")
		if err != nil {
			t.Fatal(err)
		}
		if err := write(f, tgt); err != nil {
			t.Fatal(err)
		}
		cleanup()
		if !strings.Contains(out.String(), "it-office-vlan") {
			t.Errorf("%s output lacks the vantage: %s", format, out.String())
		}
	}
	if _, _, err := scanOutput(&bytes.Buffer{}, "csv", "x"); err == nil {
		t.Error("csv with --vantage must be refused")
	}
}
