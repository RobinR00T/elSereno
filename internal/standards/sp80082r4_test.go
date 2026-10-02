package standards

import (
	"strings"
	"testing"
)

func TestForProtocol(t *testing.T) {
	refs := ForProtocol("s7-exposure")
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
	refs := ForProtocol("s7-exposure") // {refNoAuth, refSecurityOffByDefault}
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
