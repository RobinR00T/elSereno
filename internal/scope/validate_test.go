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
