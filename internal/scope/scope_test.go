package scope_test

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scope"
)

const sampleYAML = `version: 1
ranges:
  - cidr: 192.168.0.0/16
    note: lab
  - cidr: 2001:db8::/32
ports:
  allow: [502, 102, 47808]
  deny: [22]
protocols:
  allow: [modbus, s7]
binds:
  allow: ["127.0.0.1:8787"]
`

func TestLoadAndCheck(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	inScope := core.Target{
		Address: netip.MustParseAddr("192.168.1.5"),
		Port:    502,
	}
	if err := s.Check(inScope); err != nil {
		t.Fatalf("inScope Check: %v", err)
	}

	outRange := core.Target{
		Address: netip.MustParseAddr("10.0.0.1"),
		Port:    502,
	}
	if err := s.Check(outRange); !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("out-of-range: %v", err)
	}

	outPort := core.Target{
		Address: netip.MustParseAddr("192.168.1.5"),
		Port:    22,
	}
	if err := s.Check(outPort); !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("denied port: %v", err)
	}

	if err := s.CheckProtocol("modbus"); err != nil {
		t.Fatalf("allow protocol: %v", err)
	}
	if err := s.CheckProtocol("bacnet"); !errors.Is(err, scope.ErrOutOfScope) {
		t.Fatalf("denied protocol: %v", err)
	}
}

func TestLoadNilWhenEmpty(t *testing.T) {
	t.Parallel()
	s, err := scope.Load("")
	if err != nil || s != nil {
		t.Fatalf("Load(\"\") = (%v, %v), want (nil, nil)", s, err)
	}
}

func TestCheckNoScopeAlwaysOK(t *testing.T) {
	t.Parallel()
	var s *scope.Scope
	tg := core.Target{Address: netip.MustParseAddr("1.2.3.4"), Port: 1}
	if err := s.Check(tg); err != nil {
		t.Fatalf("nil scope: %v", err)
	}
}

func TestCheckDial(t *testing.T) {
	t.Parallel()
	s := &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{"44", "901", "91234567"}}}

	// Prefix match.
	if err := s.CheckDial("442071234567"); err == nil {
		t.Fatal("expected prefix block for 44…")
	}
	// Exact match.
	if err := s.CheckDial("91234567"); err == nil {
		t.Fatal("expected exact block for 91234567")
	}
	// No match.
	if err := s.CheckDial("34911234567"); err != nil {
		t.Fatalf("unblocked number should pass: %v", err)
	}
}

func TestCheckDialNilScope(t *testing.T) {
	t.Parallel()
	var s *scope.Scope
	if err := s.CheckDial("112"); err != nil {
		t.Fatalf("nil scope: %v", err)
	}
}

// TestCheckPlugin: protocols allow/deny match a plugin's name or its
// protocol (the part before the first "-"), deny wins, and a nil or
// empty scope lets every plugin run.
func TestCheckPlugin(t *testing.T) {
	cases := []struct {
		name   string
		allow  []string
		deny   []string
		plugin string
		ok     bool
	}{
		{"no lists", nil, nil, "modbus", true},
		{"allowed by name", []string{"modbus"}, nil, "modbus", true},
		{"not in allow", []string{"modbus"}, nil, "bacnet", false},
		{"family allows variant", []string{"s7"}, nil, "s7-exposure", true},
		{"variant does not allow family", []string{"s7-exposure"}, nil, "s7", false},
		{"family deny blocks variant", nil, []string{"opcua"}, "opcua-exposure", false},
		{"variant deny leaves family", nil, []string{"opcua-exposure"}, "opcua", true},
		{"opcuahttps is its own name", nil, []string{"opcua"}, "opcuahttps", true},
		{"deny wins over allow", []string{"modbus"}, []string{"modbus"}, "modbus", false},
		{"case and spaces ignored", []string{" Modbus "}, nil, "modbus", true},
		{"banner needs allowing too", []string{"modbus"}, nil, "banner", false},
	}
	for _, c := range cases {
		s := &scope.Scope{Protocols: scope.ProtoDecl{Allow: c.allow, Deny: c.deny}}
		err := s.CheckPlugin(c.plugin)
		if c.ok && err != nil {
			t.Errorf("%s: CheckPlugin(%q) = %v, want nil", c.name, c.plugin, err)
		}
		if !c.ok && !errors.Is(err, scope.ErrOutOfScope) {
			t.Errorf("%s: CheckPlugin(%q) = %v, want ErrOutOfScope", c.name, c.plugin, err)
		}
	}
	var nilScope *scope.Scope
	if err := nilScope.CheckPlugin("modbus"); err != nil {
		t.Errorf("nil scope: %v", err)
	}
}
