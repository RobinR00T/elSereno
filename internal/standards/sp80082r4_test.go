package standards

import (
	"strings"
	"testing"
)

func TestForProtocol(t *testing.T) {
	refs := ForProtocolIn(KeyNIST, "s7-exposure")
	if len(refs) != 2 {
		t.Fatalf("s7-exposure: got %d refs, want 2", len(refs))
	}
	foundNoAuth := false
	for _, r := range refs {
		if r.Standard != "NIST SP 800-82 r4" {
			t.Errorf("unexpected standard %q", r.Standard)
		}
		if r.Table == "Table 16" {
			foundNoAuth = true
		}
	}
	if !foundNoAuth {
		t.Error("s7-exposure should map to a Table 16 vulnerability")
	}

	if ForProtocol("definitely-not-a-protocol") != nil {
		t.Error("unknown protocol must return nil (no over-claiming)")
	}
}

// TestForProtocol_ReturnsCopy: a caller mutating the returned slice must
// not corrupt the shared map.
func TestForProtocol_ReturnsCopy(t *testing.T) {
	a := ForProtocol("modbus")
	if len(a) == 0 {
		t.Fatal("modbus should have a mapping")
	}
	a[0] = Ref{Standard: "mutated"}
	b := ForProtocol("modbus")
	if b[0].Standard == "mutated" {
		t.Fatal("ForProtocol returned a shared slice; mutation leaked into the map")
	}
}

func TestSummarise(t *testing.T) {
	if got := Summarise(nil); got != "" {
		t.Errorf("Summarise(nil) = %q, want empty", got)
	}
	refs := ForProtocolIn(KeyNIST, "s7-exposure") // {refNoAuth, refSecurityOffByDefault}
	got := Summarise(refs)
	if got == "" {
		t.Fatal("Summarise(s7-exposure) is empty")
	}
	// Two refs joined by "; ", each "<standard> <table>: <vuln>".
	if !strings.Contains(got, "; ") {
		t.Errorf("two refs should be joined by '; ': %q", got)
	}
	if !strings.Contains(got, "NIST SP 800-82 r4 Table 16: ") {
		t.Errorf("ref format broken: %q", got)
	}
}

func TestProtocols(t *testing.T) {
	ps := Protocols()
	if len(ps) == 0 {
		t.Fatal("Protocols() is empty")
	}
	for _, p := range ps {
		if ForProtocol(p) == nil {
			t.Errorf("Protocols() lists %q but ForProtocol returns nil", p)
		}
	}
}

func TestForProtocol_AllThreeStandardsInOrder(t *testing.T) {
	refs := ForProtocol("modbus")
	want := []string{sp80082r4, attackICS, attackICS, iec62443, iec62443, iec62443}
	if len(refs) != len(want) {
		t.Fatalf("modbus refs = %+v", refs)
	}
	for i, r := range refs {
		if r.Standard != want[i] {
			t.Errorf("ref %d standard %q, want %q", i, r.Standard, want[i])
		}
	}
	if ForProtocolIn("nope", "modbus") != nil {
		t.Error("unknown key must return nil")
	}
}

// TestAttackTechniqueIDs pins the technique IDs to the v20 names checked
// against the ics-attack STIX bundle, and keeps revoked IDs out.
func TestAttackTechniqueIDs(t *testing.T) {
	want := map[string]string{
		"T0888": "Remote System Information Discovery", "T0836": "Modify Parameter",
		"T0843": "Program Download", "T0858": "Change Operating Mode",
		"T0861": "Point & Tag Identification", "T0801": "Monitor Process State",
		"T0822": "External Remote Services", "T0886": "Remote Services",
	}
	revoked := map[string]bool{"T0812": true, "T0855": true, "T0856": true, "T0891": true}
	for proto, refs := range attackRefs {
		for _, r := range refs {
			if revoked[r.Table] {
				t.Errorf("%s uses revoked technique %s", proto, r.Table)
			}
			if want[r.Table] != r.Vuln {
				t.Errorf("%s: %s = %q, want %q", proto, r.Table, r.Vuln, want[r.Table])
			}
		}
	}
}

func TestIEC62443RequirementNumbers(t *testing.T) {
	for proto, refs := range iec62443Refs {
		for _, r := range refs {
			if r.Standard != iec62443 || !strings.HasPrefix(r.Table, "SR ") || r.Vuln == "" {
				t.Errorf("%s: malformed 62443 ref %+v", proto, r)
			}
		}
	}
}
