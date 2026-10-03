package bacnet

import (
	"net/netip"
	"strings"
	"testing"

	"local/elsereno/internal/core"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q want %q", m.Name, Name)
	}
	if m.DefaultPort != 47808 {
		t.Fatalf("DefaultPort: got %d want 47808", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "bacnet") {
		t.Fatalf("Description should mention BACnet: %q", m.Description)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{Address: netip.MustParseAddr("203.0.113.47"), Port: 47808}
	yes := buildFinding(target, "I-Am device 1234", true)
	no := buildFinding(target, "no I-Am reply", false)

	if yes.Factors["capability"] != 70 {
		t.Fatalf("capability on an I-Am: got %d want 70", yes.Factors["capability"])
	}
	if no.Factors["capability"] != 30 {
		t.Fatalf("capability without I-Am: got %d want 30", no.Factors["capability"])
	}
	if yes.Factors["cve_exposure"] != 8 {
		t.Fatalf("cve_exposure: got %d want 8", yes.Factors["cve_exposure"])
	}
	if yes.Protocol != Name {
		t.Fatalf("Protocol: got %q want %q", yes.Protocol, Name)
	}
	if yes.ID == no.ID {
		t.Fatal("distinct notes must give distinct ids")
	}
}
