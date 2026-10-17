package scope_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/scope"
)

// TestLoad_RejectsBadCIDR: a CIDR that does not parse is an error at
// load, not a silent drop at Check time (PITF-097).
func TestLoad_RejectsBadCIDR(t *testing.T) {
	for _, body := range []string{
		"version: 1\nranges:\n  - cidr: 10.0.0.0/33\n",
		"version: 1\nranges:\n  - cidr: not-a-cidr\n",
		"version: 1\nports:\n  allow: [70000]\n",
		"version: 1\nports:\n  deny: [-1]\n",
	} {
		p := filepath.Join(t.TempDir(), "scope.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := scope.Load(p); err == nil {
			t.Errorf("Load accepted an invalid scope:\n%s", body)
		}
	}
}

// TestLoad_AcceptsValidCIDR: a well-formed scope still loads.
func TestLoad_AcceptsValidCIDR(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.yaml")
	body := "version: 1\nranges:\n  - cidr: 10.0.0.0/24\n  - cidr: 2001:db8::/32\nports:\n  allow: [502, 102]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Load(p); err != nil {
		t.Fatalf("Load rejected a valid scope: %v", err)
	}
}

// TestValidate_NilAndErr: Validate is safe on nil and surfaces the bad
// entry.
func TestValidate_NilAndErr(t *testing.T) {
	var nilScope *scope.Scope
	if err := nilScope.Validate(); err != nil {
		t.Errorf("nil scope: %v", err)
	}
	s := &scope.Scope{Ranges: []scope.RangeDecl{{CIDR: "bad"}}}
	if err := s.Validate(); err == nil {
		t.Fatal("Validate accepted a bad CIDR")
	}
	_ = errors.Is
}

// TestCheckDial_NormalisesEntries: a blocked_numbers entry written with
// "+" or "00" now blocks, because both the number and the entry are
// normalised (PITF-087).
func TestCheckDial_NormalisesEntries(t *testing.T) {
	s := &scope.Scope{Dial: scope.DialDecl{BlockedNumbers: []string{"+34112", "0044 20"}}}
	for _, blocked := range []string{"34112", "34112999", "442071234567"} {
		if err := s.CheckDial(blocked); err == nil {
			t.Errorf("CheckDial(%q) = nil, want blocked", blocked)
		}
	}
	for _, ok := range []string{"34999", "33112"} {
		if err := s.CheckDial(ok); err != nil {
			t.Errorf("CheckDial(%q) = %v, want allowed", ok, err)
		}
	}
}

// TestNormaliseNumber: strips a leading +, a leading 00 and every
// non-digit.
func TestNormaliseNumber(t *testing.T) {
	cases := map[string]string{
		"+34112":    "34112",
		"0034112":   "34112",
		"34112":     "34112",
		"(555) 123": "555123",
		"+1-800":    "1800",
	}
	for in, want := range cases {
		if got := scope.NormaliseNumber(in); got != want {
			t.Errorf("NormaliseNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCheckBind: binds.allow restricts the serve bind, empty allows
// any, and IP-literal forms match after canonicalisation (PITF-087).
func TestCheckBind(t *testing.T) {
	none := &scope.Scope{}
	if err := none.CheckBind("0.0.0.0:8787"); err != nil {
		t.Errorf("empty binds.allow should allow any bind: %v", err)
	}
	s := &scope.Scope{Binds: scope.BindDecl{Allow: []string{"127.0.0.1:8787", "[::1]:8787"}}}
	for _, ok := range []string{"127.0.0.1:8787", "[0:0:0:0:0:0:0:1]:8787"} {
		if err := s.CheckBind(ok); err != nil {
			t.Errorf("CheckBind(%q) = %v, want allowed", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:8787", "127.0.0.1:9999", "10.0.0.5:8787"} {
		if err := s.CheckBind(bad); err == nil {
			t.Errorf("CheckBind(%q) = nil, want refused", bad)
		}
	}
}

// TestCheckBind_ZoneAndNonIP: a zone is stripped before comparison and a
// non-IP host compares literally (PITF-098).
func TestCheckBind_ZoneAndNonIP(t *testing.T) {
	s := &scope.Scope{Binds: scope.BindDecl{Allow: []string{"[fe80::1]:8787", "localhost:8787"}}}
	if err := s.CheckBind("[fe80::1%en0]:8787"); err != nil {
		t.Errorf("zoned IPv6 refused: %v", err)
	}
	if err := s.CheckBind("LOCALHOST:8787"); err != nil {
		t.Errorf("non-IP host (case) refused: %v", err)
	}
	if err := s.CheckBind("evil.example:8787"); err == nil {
		t.Error("a host not in the list was allowed")
	}
}
