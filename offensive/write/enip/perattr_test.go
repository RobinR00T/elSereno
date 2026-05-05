//go:build offensive

package enip

import (
	"testing"

	enipwire "local/elsereno/internal/protocols/enip/wire"
)

func TestAllowedAttribute_MatchesExact(t *testing.T) {
	a := AllowedAttribute{Class: 1, Instance: 2, Attribute: 7, MatchType: MatchExact}
	cases := []struct {
		name string
		t    enipwire.EPathTarget
		want bool
	}{
		{"all match", enipwire.EPathTarget{Class: 1, Instance: 2, Attribute: 7, HasClass: true, HasInstance: true, HasAttr: true}, true},
		{"wrong attr", enipwire.EPathTarget{Class: 1, Instance: 2, Attribute: 8, HasClass: true, HasInstance: true, HasAttr: true}, false},
		{"missing attr", enipwire.EPathTarget{Class: 1, Instance: 2, HasClass: true, HasInstance: true}, false},
		{"wrong instance", enipwire.EPathTarget{Class: 1, Instance: 3, Attribute: 7, HasClass: true, HasInstance: true, HasAttr: true}, false},
		{"wrong class", enipwire.EPathTarget{Class: 2, Instance: 2, Attribute: 7, HasClass: true, HasInstance: true, HasAttr: true}, false},
	}
	for _, c := range cases {
		if got := a.Matches(c.t); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAllowedAttribute_MatchesClassInstance(t *testing.T) {
	a := AllowedAttribute{Class: 4, Instance: 1, MatchType: MatchClassInstance}
	cases := []struct {
		name string
		t    enipwire.EPathTarget
		want bool
	}{
		{"class+inst with attr", enipwire.EPathTarget{Class: 4, Instance: 1, Attribute: 99, HasClass: true, HasInstance: true, HasAttr: true}, true},
		{"class+inst no attr", enipwire.EPathTarget{Class: 4, Instance: 1, HasClass: true, HasInstance: true}, true},
		{"wrong instance", enipwire.EPathTarget{Class: 4, Instance: 2, HasClass: true, HasInstance: true}, false},
		{"missing instance", enipwire.EPathTarget{Class: 4, HasClass: true}, false},
	}
	for _, c := range cases {
		if got := a.Matches(c.t); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAllowedAttribute_MatchesClassOnly(t *testing.T) {
	a := AllowedAttribute{Class: 0x0142, MatchType: MatchClassOnly}
	cases := []struct {
		name string
		t    enipwire.EPathTarget
		want bool
	}{
		{"class only", enipwire.EPathTarget{Class: 0x0142, HasClass: true}, true},
		{"class+inst+attr", enipwire.EPathTarget{Class: 0x0142, Instance: 99, Attribute: 8, HasClass: true, HasInstance: true, HasAttr: true}, true},
		{"wrong class", enipwire.EPathTarget{Class: 0x0143, HasClass: true}, false},
	}
	for _, c := range cases {
		if got := a.Matches(c.t); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAllowlistHash_BackcompatEmptyAttrs(t *testing.T) {
	target := "10.0.0.1:44818"
	allowed := []AllowedCommand{{Cmd: enipwire.CmdSendRRData}, {Cmd: enipwire.CmdRegisterSession}}
	withAttrs := AllowlistHash(target, allowed, nil)
	legacy := SessionMutationLegacy(target, allowed).PayloadHash
	if withAttrs != legacy {
		t.Errorf("empty-attrs hash differs from legacy")
	}
}

func TestAllowlistHash_DifferentAttrs(t *testing.T) {
	target := "10.0.0.1:44818"
	allowed := []AllowedCommand{{Cmd: enipwire.CmdSendRRData}}
	a := []AllowedAttribute{{Class: 1, Instance: 1, Attribute: 7, MatchType: MatchExact}}
	b := []AllowedAttribute{{Class: 1, Instance: 1, Attribute: 8, MatchType: MatchExact}}
	if AllowlistHash(target, allowed, a) == AllowlistHash(target, allowed, b) {
		t.Errorf("changing attribute did not change hash")
	}
}

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	target := "10.0.0.1:44818"
	allowed := []AllowedCommand{{Cmd: enipwire.CmdSendRRData}}
	a := []AllowedAttribute{
		{Class: 1, Instance: 1, Attribute: 7, MatchType: MatchExact},
		{Class: 4, Instance: 0, MatchType: MatchClassOnly},
	}
	b := []AllowedAttribute{
		{Class: 4, Instance: 0, MatchType: MatchClassOnly},
		{Class: 1, Instance: 1, Attribute: 7, MatchType: MatchExact},
	}
	if AllowlistHash(target, allowed, a) != AllowlistHash(target, allowed, b) {
		t.Errorf("order-sensitive")
	}
}
