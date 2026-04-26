//go:build offensive

package main

import (
	"testing"

	iaxwire "local/elsereno/internal/protocols/iax2/wire"
	bacwrite "local/elsereno/offensive/write/bacnet"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
	iaxwrite "local/elsereno/offensive/write/iax2"
	opwrite "local/elsereno/offensive/write/opcua"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	sipwrite "local/elsereno/offensive/write/sip"
)

// TestCanonicaliseTarget_IPv6FormsConverge — the canonical
// safety invariant of v1.14 chunk 2: longform / shortform /
// uppercase IPv6 host:port literals all map to the same string.
// An operator who writes `[0:0:0:0:0:0:0:1]:7547` in dry-run
// and `[::1]:7547` in `proxy listen` (or vice-versa) sees both
// produce the same hash → confirm-token matches.
func TestCanonicaliseTarget_IPv6FormsConverge(t *testing.T) {
	cases := []struct {
		name   string
		inputs []string
		want   string
	}{
		{
			name: "v6 loopback longform vs shortform",
			inputs: []string{
				"[::1]:7547",
				"[0:0:0:0:0:0:0:1]:7547",
				"[0000:0000:0000:0000:0000:0000:0000:0001]:7547",
			},
			want: "[::1]:7547",
		},
		{
			name: "v6 documentation prefix uppercase vs lowercase",
			inputs: []string{
				"[2001:db8::1]:443",
				"[2001:DB8::1]:443",
				"[2001:0db8:0000:0000:0000:0000:0000:0001]:443",
			},
			want: "[2001:db8::1]:443",
		},
		{
			name: "v4 unchanged",
			inputs: []string{
				"127.0.0.1:7547",
			},
			want: "127.0.0.1:7547",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range tc.inputs {
				got := canonicaliseTarget(input)
				if got != tc.want {
					t.Errorf("canonicaliseTarget(%q) = %q, want %q", input, got, tc.want)
				}
			}
		})
	}
}

// TestCanonicaliseTarget_HostnameUnchanged — hostname forms pass
// through unchanged (no DNS resolution at parse time).
func TestCanonicaliseTarget_HostnameUnchanged(t *testing.T) {
	cases := []string{
		"localhost:7547",
		"plc.example.com:502",
		"bms.internal:47808",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			got := canonicaliseTarget(s)
			if got != s {
				t.Errorf("hostname %q canonicalised to %q (should pass through)", s, got)
			}
		})
	}
}

// TestCanonicaliseTarget_EmptyUnchanged — empty input returns
// empty (validation happens elsewhere).
func TestCanonicaliseTarget_EmptyUnchanged(t *testing.T) {
	if got := canonicaliseTarget(""); got != "" {
		t.Errorf("canonicaliseTarget(\"\") = %q, want \"\"", got)
	}
}

// ---- Hash-equivalence regressions ---------------------------
//
// The downstream contract: if two equivalent IPv6 forms are
// canonicalised to the same string, the SessionMutation hashes
// must match. Without canonicalisation an operator hits an
// "expected token X, got Y" mismatch on the first proxy-listen
// run, which is brutal UX. These tests pin the equivalence
// per-plugin.

func TestSessionMutationsMatchAcrossIPv6Forms_BACnet(t *testing.T) {
	target1 := canonicaliseTarget("[0:0:0:0:0:0:0:1]:47808")
	target2 := canonicaliseTarget("[::1]:47808")
	if target1 != target2 {
		t.Fatalf("targets diverged: %q vs %q", target1, target2)
	}
	svcs := []bacwrite.AllowedService{{ServiceChoice: 15}}
	m1 := bacwrite.SessionMutation(target1, svcs)
	m2 := bacwrite.SessionMutation(target2, svcs)
	if m1.PayloadHash != m2.PayloadHash {
		t.Errorf("BACnet hash mismatch: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}

func TestSessionMutationsMatchAcrossIPv6Forms_OPCUA(t *testing.T) {
	target1 := canonicaliseTarget("[0:0:0:0:0:0:0:1]:4840")
	target2 := canonicaliseTarget("[::1]:4840")
	svcs := []opwrite.AllowedService{{TypeID: 673}}
	m1 := opwrite.SessionMutation(target1, svcs)
	m2 := opwrite.SessionMutation(target2, svcs)
	if m1.PayloadHash != m2.PayloadHash {
		t.Errorf("OPC UA hash mismatch: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}

func TestSessionMutationsMatchAcrossIPv6Forms_SIP(t *testing.T) {
	target1 := canonicaliseTarget("[0:0:0:0:0:0:0:1]:5060")
	target2 := canonicaliseTarget("[::1]:5060")
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	m1 := sipwrite.SessionMutation(target1, methods)
	m2 := sipwrite.SessionMutation(target2, methods)
	if m1.PayloadHash != m2.PayloadHash {
		t.Errorf("SIP hash mismatch: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}

func TestSessionMutationsMatchAcrossIPv6Forms_IAX2(t *testing.T) {
	target1 := canonicaliseTarget("[0:0:0:0:0:0:0:1]:4569")
	target2 := canonicaliseTarget("[::1]:4569")
	subs := []iaxwrite.AllowedSubclass{{Subclass: iaxwire.IAXNew}}
	m1 := iaxwrite.SessionMutation(target1, subs)
	m2 := iaxwrite.SessionMutation(target2, subs)
	if m1.PayloadHash != m2.PayloadHash {
		t.Errorf("IAX2 hash mismatch: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}

func TestSessionMutationsMatchAcrossIPv6Forms_PBXHTTP(t *testing.T) {
	target1 := canonicaliseTarget("[0:0:0:0:0:0:0:1]:443")
	target2 := canonicaliseTarget("[::1]:443")
	allowed := []pbxwrite.AllowedWrite{{Method: "POST", Path: "/admin"}}
	m1 := pbxwrite.SessionMutation(target1, allowed)
	m2 := pbxwrite.SessionMutation(target2, allowed)
	if m1.PayloadHash != m2.PayloadHash {
		t.Errorf("pbxhttp hash mismatch: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}

func TestSessionMutationsMatchAcrossIPv6Forms_CWMP(t *testing.T) {
	target1 := canonicaliseTarget("[0:0:0:0:0:0:0:1]:7547")
	target2 := canonicaliseTarget("[::1]:7547")
	rpcs := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	m1 := cwmpwrite.SessionMutation(target1, rpcs)
	m2 := cwmpwrite.SessionMutation(target2, rpcs)
	if m1.PayloadHash != m2.PayloadHash {
		t.Errorf("CWMP hash mismatch: %x vs %x", m1.PayloadHash, m2.PayloadHash)
	}
}
