package twincat

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/twincat/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q want %q", m.Name, Name)
	}
	if m.DefaultPort != 48898 {
		t.Fatalf("DefaultPort: got %d want 48898", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "twincat") {
		t.Fatalf("Description should mention TwinCAT: %q", m.Description)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{Address: netip.MustParseAddr("203.0.113.48"), Port: 48898}
	yes := buildFinding(target, "TwinCAT TC3 PLC1 3.1.4024", true)
	no := buildFinding(target, "no usable reply", false)

	if yes.Factors["capability"] != 70 {
		t.Fatalf("capability on a TwinCAT reply: got %d want 70", yes.Factors["capability"])
	}
	if no.Factors["capability"] != 30 {
		t.Fatalf("capability without a reply: got %d want 30", no.Factors["capability"])
	}
	if yes.Factors["cve_exposure"] != 10 {
		t.Fatalf("cve_exposure: got %d want 10", yes.Factors["cve_exposure"])
	}
	if yes.Protocol != Name {
		t.Fatalf("Protocol: got %q want %q", yes.Protocol, Name)
	}
	if yes.ID == no.ID {
		t.Fatal("distinct notes must give distinct ids")
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short AMS reply"},
		{wire.ErrBadAMSTCP, "non-AMS reply"},
		{wire.ErrLengthMismatch, "AMS length mismatch"},
		{wire.ErrNotADSResponse, "not a ReadDeviceInfo response"},
		{errors.New("anything else"), "AMS classify failure"},
	}
	for _, c := range cases {
		if got := classifyParseError(c.err); !strings.Contains(got, c.want) {
			t.Errorf("classifyParseError(%v) = %q, want substring %q", c.err, got, c.want)
		}
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}
