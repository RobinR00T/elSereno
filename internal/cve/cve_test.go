package cve

import "testing"

func TestS7Family(t *testing.T) {
	cases := map[string]string{
		"6ES7 515-2AM01-0AB0": "s7-1500",
		"6ES7 212-1AE40-0XB0": "s7-1200",
		"6ES7 315-2EH14-0AB0": "s7-300",
		"6ES7 416-3ES07-0AB0": "s7-400",
		"6ES7515-2AM01-0AB0":  "s7-1500", // no space
		// ET200 distributed CPUs are deliberately unclassified (151 = ET200S
		// is S7-300-class; 155 = ET200SP is S7-1500-class; one digit can't tell).
		"6ES7 151-8AB01-0AB0": "",
		"6ES7 155-6AU01-0CN0": "",
		"":                    "",
		"not-an-mlfb":         "",
	}
	for in, want := range cases {
		if got := S7Family(in); got != want {
			t.Errorf("S7Family(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestForS7(t *testing.T) {
	recs := ForS7("6ES7 515-2AM01-0AB0")
	if len(recs) == 0 {
		t.Fatal("S7-1500 should have curated CVEs")
	}
	if recs[0].ID != "CVE-2020-15782" {
		t.Errorf("S7-1500 first CVE = %q, want CVE-2020-15782", recs[0].ID)
	}
	if got := ForS7("6ES7 315-2EH14-0AB0"); len(got) == 0 || got[0].ID != "CVE-2016-9158" {
		t.Errorf("S7-300 CVEs = %+v, want CVE-2016-9158 first", got)
	}
	// ET200 / unknown: no over-claim.
	if got := ForS7("6ES7 151-8AB01-0AB0"); got != nil {
		t.Errorf("ET200S must not map to CVEs, got %+v", got)
	}
}

func TestForENIP(t *testing.T) {
	// Rockwell (vendor 1) ControlLogix Ethernet modules carry CVE-2025-7353.
	// EN2T / EN2TR / EN2TP all contain "EN2T"; EN2F and EN3TR match explicitly.
	for _, name := range []string{
		"1756-EN2T/D", "1756-EN2TR/C", "1756-EN2TP/A", "1756-EN2F/C", "1756-EN3TR/B",
	} {
		recs := ForENIP(1, name)
		if len(recs) != 1 || recs[0].ID != "CVE-2025-7353" {
			t.Errorf("ForENIP(1, %q) = %+v, want CVE-2025-7353", name, recs)
		}
	}
	// The older 1756-ENBT (the validated real-capture device) is NOT in the
	// affected list: no over-claim, it must return nil.
	if got := ForENIP(1, "1756-ENBT/A"); got != nil {
		t.Errorf("1756-ENBT must not map to CVEs, got %+v", got)
	}
	// Same catalog token but a different vendor: not Rockwell, no match.
	if got := ForENIP(42, "1756-EN2T/D"); got != nil {
		t.Errorf("non-Rockwell vendor must not map to Rockwell CVEs, got %+v", got)
	}
	if got := ForENIP(1, ""); got != nil {
		t.Errorf("empty product name must not map to CVEs, got %+v", got)
	}
}

func TestScore(t *testing.T) {
	if Score(nil) != 0 {
		t.Error("no records must score 0")
	}
	// One 8.1 CVE: base 45, no critical bump.
	if s := Score([]Record{{ID: "CVE-2020-15782", CVSS: 8.1}}); s != 45 {
		t.Errorf("one high CVE scored %d, want 45", s)
	}
	// Two records, one critical: 45 + 10 + 15 = 70.
	s := Score([]Record{{ID: "a", CVSS: 7.5}, {ID: "b", CVSS: 9.8}})
	if s != 70 {
		t.Errorf("two records (one critical) scored %d, want 70", s)
	}
	// Cap at 90.
	many := make([]Record, 10)
	for i := range many {
		many[i] = Record{ID: "x", CVSS: 9.9}
	}
	if s := Score(many); s != 90 {
		t.Errorf("many critical records scored %d, want cap 90", s)
	}
}

func TestIDs(t *testing.T) {
	got := IDs([]Record{{ID: "CVE-1"}, {ID: "CVE-2"}})
	if len(got) != 2 || got[0] != "CVE-1" || got[1] != "CVE-2" {
		t.Errorf("IDs = %v", got)
	}
}
