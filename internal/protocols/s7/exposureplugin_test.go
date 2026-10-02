package s7

import (
	"net/netip"
	"testing"

	"local/elsereno/internal/core"
)

func exposureTarget() core.Target {
	return core.Target{Address: netip.MustParseAddr("192.0.2.10"), Port: 102}
}

func TestBuildExposureFinding_Scoring(t *testing.T) {
	tg := exposureTarget()

	exposed := buildExposureFinding(tg, PostureResult{
		IsS7: true, SetupOK: true, ProtectionRead: true, Exposed: true,
		OrderNumber: "6ES7 151-8AB01-0AB0", Firmware: "V3.2.6",
	})
	protected := buildExposureFinding(tg, PostureResult{
		IsS7: true, SetupOK: true, ProtectionRead: true, Exposed: false,
		OrderNumber: "6ES7 151-8AB01-0AB0", Firmware: "V3.2.6",
	})
	unreadable := buildExposureFinding(tg, PostureResult{
		IsS7: true, SetupOK: true, ProtectionRead: false,
	})
	notS7 := buildExposureFinding(tg, PostureResult{})

	// The exposed CPU (writable without a password) must score highest and
	// land at Critical severity; a protected CPU scores lower.
	if exposed.Factors["auth_state"] != 95 || exposed.Factors["exposure"] != 95 {
		t.Errorf("exposed factors = %v, want auth_state/exposure 95", exposed.Factors)
	}
	if exposed.Severity != core.SeverityCritical {
		t.Errorf("exposed severity = %s (score %d), want critical", exposed.Severity, exposed.Score)
	}
	if exposed.Score <= protected.Score {
		t.Errorf("exposed score %d should exceed protected score %d", exposed.Score, protected.Score)
	}
	if protected.Score <= notS7.Score {
		t.Errorf("protected score %d should exceed not-s7 score %d", protected.Score, notS7.Score)
	}
	// The protected CPU enforces a password: its auth_state factor is low.
	if protected.Factors["auth_state"] != 35 {
		t.Errorf("protected auth_state = %d, want 35", protected.Factors["auth_state"])
	}
	// Distinct states must produce distinct finding IDs (via the note hash).
	if exposed.ID == protected.ID || exposed.ID == unreadable.ID {
		t.Error("distinct posture states must yield distinct finding IDs")
	}
	if exposed.Protocol != ExposureName {
		t.Errorf("protocol = %q, want %q", exposed.Protocol, ExposureName)
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
