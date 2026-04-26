package scanner_test

import (
	"net/netip"
	"testing"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
)

// TestDedupe_IPv4MappedIPv6CollapsesWithBareV4 — the canonical
// chunk-4 invariant for the dedupe layer: an IPv4-mapped IPv6
// address (`::ffff:1.2.3.4`) and the bare IPv4 form (`1.2.3.4`)
// represent the same target — Dedupe must collapse them via
// .Unmap() so the scanner doesn't probe twice.
func TestDedupe_IPv4MappedIPv6CollapsesWithBareV4(t *testing.T) {
	in := []core.Target{
		{Address: netip.MustParseAddr("::ffff:1.2.3.4"), Port: 502},
		{Address: netip.MustParseAddr("1.2.3.4"), Port: 502},
		{Address: netip.MustParseAddr("1.2.3.4"), Port: 502}, // exact dup
	}
	out := scanner.Dedupe(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduplicated target, got %d: %+v", len(out), out)
	}
	// The surviving entry must be the bare-v4 form (post-Unmap).
	if out[0].Address.String() != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", out[0].Address.String())
	}
}

// TestDedupe_IPv6FormsCollapse — netip.Addr stores IPv6 in its
// canonical form internally, so longform / shortform inputs
// dedup correctly without needing an explicit canonicaliser
// call. Pin the contract.
func TestDedupe_IPv6FormsCollapse(t *testing.T) {
	in := []core.Target{
		{Address: netip.MustParseAddr("::1"), Port: 7547},
		{Address: netip.MustParseAddr("0:0:0:0:0:0:0:1"), Port: 7547}, // longform
	}
	out := scanner.Dedupe(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduplicated target, got %d", len(out))
	}
	if out[0].Address.String() != "::1" {
		t.Errorf("expected canonical '::1', got %q", out[0].Address.String())
	}
}

// TestDedupe_IPv6vsIPv4DistinctTargets — `::1:7547` and
// `127.0.0.1:7547` are SEPARATE targets (different families).
// Dedupe must NOT collapse them.
func TestDedupe_IPv6vsIPv4DistinctTargets(t *testing.T) {
	in := []core.Target{
		{Address: netip.MustParseAddr("::1"), Port: 7547},
		{Address: netip.MustParseAddr("127.0.0.1"), Port: 7547},
	}
	out := scanner.Dedupe(in)
	if len(out) != 2 {
		t.Errorf("v6 loopback and v4 loopback must not collapse, got %d targets", len(out))
	}
}

// TestDedupe_DifferentPortsKept — same IPv6 address on two
// ports stays as two targets.
func TestDedupe_DifferentPortsKept(t *testing.T) {
	in := []core.Target{
		{Address: netip.MustParseAddr("2001:db8::1"), Port: 502},
		{Address: netip.MustParseAddr("2001:db8::1"), Port: 7547},
	}
	out := scanner.Dedupe(in)
	if len(out) != 2 {
		t.Errorf("different ports must not collapse, got %d targets", len(out))
	}
}
