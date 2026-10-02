package opcua

import (
	"net/netip"
	"testing"

	"local/elsereno/internal/core"
)

func exposureTarget() core.Target {
	return core.Target{Address: netip.MustParseAddr("192.0.2.20"), Port: 4840}
}

func TestBuildExposureFinding_Scoring(t *testing.T) {
	tg := exposureTarget()

	writeable := buildExposureFinding(tg, WriteableWalkResult{
		AnonymousAccessResult: AnonymousAccessResult{IsOPCUA: true, SessionOpened: true},
		VariablesRead:         12,
		Writeable:             []WriteableNode{{NodeID: "ns=2;s=Setpoint", BrowseName: "Setpoint", UserAccessLevel: 0x03}},
	})
	anonOpen := buildExposureFinding(tg, WriteableWalkResult{
		AnonymousAccessResult: AnonymousAccessResult{IsOPCUA: true, SessionOpened: true},
		VariablesRead:         12,
	})
	anonBlocked := buildExposureFinding(tg, WriteableWalkResult{
		AnonymousAccessResult: AnonymousAccessResult{IsOPCUA: true, SessionOpened: false},
	})
	notOPCUA := buildExposureFinding(tg, WriteableWalkResult{})

	// A writeable tag reachable by the anonymous user is the exposure: it
	// must score highest and land at Critical.
	if writeable.Factors["auth_state"] != 95 || writeable.Factors["exposure"] != 95 {
		t.Errorf("writeable factors = %v, want auth_state/exposure 95", writeable.Factors)
	}
	if writeable.Severity != core.SeverityCritical {
		t.Errorf("writeable severity = %s (score %d), want critical", writeable.Severity, writeable.Score)
	}
	// An anonymous session that opens (but exposes no writeable tag) is a
	// High-severity exposure: unauthenticated access to the control plane.
	if anonOpen.Severity != core.SeverityHigh {
		t.Errorf("anon-open severity = %s (score %d), want high", anonOpen.Severity, anonOpen.Score)
	}
	// Strict ordering: writeable > anon-open > anon-blocked > not-opcua.
	ordered := writeable.Score > anonOpen.Score &&
		anonOpen.Score > anonBlocked.Score &&
		anonBlocked.Score > notOPCUA.Score
	if !ordered {
		t.Errorf("score ordering broken: writeable=%d anon-open=%d anon-blocked=%d not-opcua=%d",
			writeable.Score, anonOpen.Score, anonBlocked.Score, notOPCUA.Score)
	}
	// Distinct states must produce distinct finding IDs (via the note hash).
	if writeable.ID == anonOpen.ID || anonOpen.ID == anonBlocked.ID || anonBlocked.ID == notOPCUA.ID {
		t.Error("distinct exposure states must yield distinct finding IDs")
	}
	if writeable.Protocol != ExposureName {
		t.Errorf("protocol = %q, want %q", writeable.Protocol, ExposureName)
	}
}

func TestExposurePlugin_Metadata_OptIn(t *testing.T) {
	m := DefaultExposure().Metadata()
	if m.Name != ExposureName {
		t.Errorf("name = %q, want %q", m.Name, ExposureName)
	}
	// DefaultPort 0 is what keeps it out of the default scan/discover sweep.
	if m.DefaultPort != 0 {
		t.Errorf("DefaultPort = %d, want 0 (opt-in only)", m.DefaultPort)
	}
	// OptIn keeps it out of a scanorch "run everything" job too.
	if !m.OptIn {
		t.Error("OptIn = false, want true (never swept by default)")
	}
	if m.Build != "default" {
		t.Errorf("build = %q, want default", m.Build)
	}
}
