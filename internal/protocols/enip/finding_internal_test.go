package enip

import (
	"net/netip"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/enip/wire"
)

func enipTarget() core.Target {
	return core.Target{Address: netip.MustParseAddr("192.0.2.20"), Port: 44818}
}

func TestBuildFinding_CVEEnrichment(t *testing.T) {
	tg := enipTarget()
	base := "ListIdentity: vendor=1 product=rockwell"

	// Rockwell ControlLogix Ethernet module (EN2TR): a curated real CVE
	// (CVE-2025-7353, CVSS 9.8) raises cve_exposure to Score([one critical]) = 60.
	en2tr := buildFinding(tg, base, &wire.IdentityItem{VendorID: 1, ProductName: "1756-EN2TR/C"})
	// The validated real-capture device (1756-ENBT/A): Rockwell, but NOT in the
	// affected list, so it stays at the family baseline with no CVE boost.
	enbt := buildFinding(tg, base, &wire.IdentityItem{VendorID: 1, ProductName: "1756-ENBT/A"})

	if en2tr.Factors["cve_exposure"] != 60 {
		t.Errorf("EN2TR cve_exposure = %d, want 60 (one critical CVE)", en2tr.Factors["cve_exposure"])
	}
	if enbt.Factors["cve_exposure"] != 11 {
		t.Errorf("ENBT cve_exposure = %d, want family baseline 11", enbt.Factors["cve_exposure"])
	}
	// The enriched note ("... cve=CVE-2025-7353") keys a distinct finding id.
	if en2tr.ID == enbt.ID {
		t.Error("CVE-enriched finding should have a distinct id from the baseline one")
	}
	if en2tr.Protocol != Name {
		t.Errorf("protocol = %q, want %q", en2tr.Protocol, Name)
	}
}
