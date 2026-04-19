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
