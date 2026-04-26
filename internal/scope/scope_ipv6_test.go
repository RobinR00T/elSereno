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

// scopeWithIPv6Ranges is a fixture used by every test in this
// file. The lab range covers IPv4 (192.168/16) plus the
// IPv6 documentation prefix (2001:db8::/32) per RFC 3849. The
// loopback range (::1/128) is also included so we can exercise
// the host-prefix match.
const scopeWithIPv6Ranges = `version: 1
ranges:
  - cidr: 192.168.0.0/16
    note: lab
  - cidr: 2001:db8::/32
    note: docs prefix
  - cidr: ::1/128
    note: ipv6 loopback
ports:
  allow: [502, 47808, 7547]
`

func loadIPv6Scope(t *testing.T) *scope.Scope {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte(scopeWithIPv6Ranges), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return s
}

// TestCheck_IPv6_InRange — IPv6 target inside the documentation
// prefix matches the IPv6 CIDR. The canonical safety invariant
// of v1.14 chunk 4: IPv6 ranges declared in scope.yaml actually
// gate IPv6 targets.
func TestCheck_IPv6_InRange(t *testing.T) {
	s := loadIPv6Scope(t)
	tg := core.Target{
		Address: netip.MustParseAddr("2001:db8::1"),
		Port:    502,
	}
	if err := s.Check(tg); err != nil {
		t.Errorf("expected in-scope, got: %v", err)
	}
}

// TestCheck_IPv6_LoopbackHostPrefix — host-prefix /128 is
// honoured (the chunk-1 IsLoopbackHostPort already detects
// loopback for bind addresses; here we verify scope.yaml
// can also gate scanning the loopback target).
func TestCheck_IPv6_LoopbackHostPrefix(t *testing.T) {
	s := loadIPv6Scope(t)
	tg := core.Target{
		Address: netip.MustParseAddr("::1"),
		Port:    7547,
	}
	if err := s.Check(tg); err != nil {
		t.Errorf("loopback host prefix should match ::1/128: %v", err)
	}
}

// TestCheck_IPv6_OutOfRange — IPv6 target outside the declared
// ranges returns ErrOutOfScope.
func TestCheck_IPv6_OutOfRange(t *testing.T) {
	s := loadIPv6Scope(t)
	tg := core.Target{
		Address: netip.MustParseAddr("fe80::1"), // link-local — not in scope
		Port:    502,
	}
	err := s.Check(tg)
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("expected ErrOutOfScope, got: %v", err)
	}
}

// TestCheck_IPv4MappedIPv6_MatchesV4Range — `::ffff:192.168.1.5`
// (IPv4-mapped IPv6) must match the v4 CIDR `192.168.0.0/16`
// via .Unmap() canonicalisation. Without this the operator
// could bypass scope by using the v4-mapped form.
func TestCheck_IPv4MappedIPv6_MatchesV4Range(t *testing.T) {
	s := loadIPv6Scope(t)
	mapped := netip.MustParseAddr("::ffff:192.168.1.5")
	tg := core.Target{
		Address: mapped,
		Port:    502,
	}
	if err := s.Check(tg); err != nil {
		t.Errorf("v4-mapped target should match v4 range via Unmap: %v", err)
	}
}

// TestCheck_IPv4Target_DoesNotMatchIPv6Range — the inverse: a
// pure IPv4 target like 1.2.3.4 must NOT match an IPv6 prefix
// like 2001:db8::/32 just because the prefix would syntactically
// contain its v4-mapped form. Verifies that scope ranges
// don't leak across address families.
func TestCheck_IPv4Target_DoesNotMatchIPv6Range(t *testing.T) {
	yaml := `version: 1
ranges:
  - cidr: 2001:db8::/32
ports:
  allow: [502]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := scope.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	tg := core.Target{
		Address: netip.MustParseAddr("1.2.3.4"),
		Port:    502,
	}
	err = s.Check(tg)
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("v4 target must not match v6-only scope, got: %v", err)
	}
}
