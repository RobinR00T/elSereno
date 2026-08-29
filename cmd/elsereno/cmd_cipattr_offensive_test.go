//go:build offensive

package main

import (
	"testing"

	enipwrite "local/elsereno/offensive/write/enip"
)

// --cip-attr tightens the ENIP gate to a CIP object; the MatchType is
// inferred from which of class/instance/attr are present.
func TestParseCIPAttr(t *testing.T) {
	a, err := parseCIPAttr("class=0x6B")
	if err != nil || a.Class != 0x6B || a.MatchType != enipwrite.MatchClassOnly {
		t.Fatalf("class-only: %+v err %v", a, err)
	}
	a, err = parseCIPAttr("class=107;instance=1")
	if err != nil || a.Class != 107 || a.Instance != 1 || a.MatchType != enipwrite.MatchClassInstance {
		t.Fatalf("class+instance: %+v err %v", a, err)
	}
	a, err = parseCIPAttr("class=0x6B;instance=1;attr=3")
	if err != nil || a.Attribute != 3 || a.MatchType != enipwrite.MatchExact {
		t.Fatalf("exact: %+v err %v", a, err)
	}
	if _, err := parseCIPAttr("instance=1"); err == nil {
		t.Fatal("missing class: want error")
	}
	if _, err := parseCIPAttr("class=1;foo=2"); err == nil {
		t.Fatal("unknown key: want error")
	}
	if _, err := parseCIPAttr("class=xyz"); err == nil {
		t.Fatal("bad number: want error")
	}
}
