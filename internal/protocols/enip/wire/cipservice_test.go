package wire

import "testing"

func TestClassifyCIPService_GenericCommonServices(t *testing.T) {
	// Common services (CIP Vol 1 Appendix A) resolve without a class.
	cases := []struct {
		name    string
		service byte
		want    ServiceKind
	}{
		{"get_attribute_single", 0x0E, ServiceKindRead},
		{"get_attributes_all", 0x01, ServiceKindRead},
		{"set_attribute_single", 0x10, ServiceKindWrite},
		{"reset", 0x05, ServiceKindAdmin},
		{"stop", 0x07, ServiceKindAdmin},
		{"start", 0x06, ServiceKindAdmin},
		{"multiple_service_packet", 0x0A, ServiceKindUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ClassifyCIPService(tc.service, EPathTarget{})
			if got != tc.want {
				t.Fatalf("service 0x%02x: got %v, want %v", tc.service, got, tc.want)
			}
		})
	}
}

// The core lesson: the same service byte flips meaning by object class.
func TestClassifyCIPService_ClassScopedDisambiguation(t *testing.T) {
	connMgr := EPathTarget{Class: ClassConnectionManager, HasClass: true}
	symbol := EPathTarget{Class: ClassSymbol, HasClass: true}

	// 0x52 is Unconnected_Send in the Connection Manager but Read Tag
	// Fragmented against a tag/Symbol object.
	if k, scoped := ClassifyCIPService(0x52, connMgr); k != ServiceKindConnection || !scoped {
		t.Fatalf("0x52 @ ConnMgr: got %v scoped=%v, want connection/true", k, scoped)
	}
	if k, scoped := ClassifyCIPService(0x52, symbol); k != ServiceKindRead || !scoped {
		t.Fatalf("0x52 @ Symbol: got %v scoped=%v, want read/true", k, scoped)
	}

	// 0x4E is Forward_Close in the Connection Manager but Read-Modify-
	// Write Tag (a write) against the Symbol object.
	if k, _ := ClassifyCIPService(0x4E, connMgr); k != ServiceKindConnection {
		t.Fatalf("0x4E @ ConnMgr: got %v, want connection", k)
	}
	if k, _ := ClassifyCIPService(0x4E, symbol); k != ServiceKindWrite {
		t.Fatalf("0x4E @ Symbol: got %v, want write", k)
	}
}

// Without a class, an ambiguous vendor byte must not be labelled with
// confidence: the false-positive guard.
func TestClassifyCIPService_UnscopedIsLowConfidence(t *testing.T) {
	// 0x4D (Write Tag) resolves to write even unscoped, but the scoped
	// flag must be false so scoring down-weights it.
	if k, scoped := ClassifyCIPService(0x4D, EPathTarget{}); k != ServiceKindWrite || scoped {
		t.Fatalf("0x4D unscoped: got %v scoped=%v, want write/false", k, scoped)
	}
	// 0x4E and 0x52 are unresolvable without a class.
	for _, b := range []byte{0x4E, 0x52} {
		if k, scoped := ClassifyCIPService(b, EPathTarget{}); k != ServiceKindUnknown || scoped {
			t.Fatalf("0x%02x unscoped: got %v scoped=%v, want unknown/false", b, k, scoped)
		}
	}
}

func TestServiceObservation_FalseZeroRule(t *testing.T) {
	// No traffic at all is "blind", never "clean".
	var blind ServiceObservation
	if v := blind.Verdict(); v != VerdictBlind {
		t.Fatalf("empty observation: got %v, want blind", v)
	}

	// Reads present, no writes: the zero-write is now trustworthy.
	clean := ServiceObservation{Reads: 3}
	if v := clean.Verdict(); v != VerdictClean {
		t.Fatalf("reads-only: got %v, want clean", v)
	}

	// Only a connection seen, no writes: still clean (we had a vantage).
	connOnly := ServiceObservation{Connections: 1}
	if v := connOnly.Verdict(); v != VerdictClean {
		t.Fatalf("connection-only: got %v, want clean", v)
	}

	// A single admin service flips the verdict to active.
	active := ServiceObservation{Reads: 10, Admin: 1}
	if v := active.Verdict(); v != VerdictActive {
		t.Fatalf("reads+admin: got %v, want active", v)
	}

	// Unknown-only traffic is not enough to claim clean.
	unknownOnly := ServiceObservation{Unknown: 5}
	if v := unknownOnly.Verdict(); v != VerdictBlind {
		t.Fatalf("unknown-only: got %v, want blind", v)
	}
}

func TestServiceObservation_Observe(t *testing.T) {
	var o ServiceObservation
	o.Observe(ServiceKindRead)
	o.Observe(ServiceKindWrite)
	o.Observe(ServiceKindWrite)
	o.Observe(ServiceKindAdmin)
	o.Observe(ServiceKindConnection)
	o.Observe(ServiceKindUnknown)
	if o.Reads != 1 || o.Writes != 2 || o.Admin != 1 || o.Connections != 1 || o.Unknown != 1 {
		t.Fatalf("counts wrong: %+v", o)
	}
	if v := o.Verdict(); v != VerdictActive {
		t.Fatalf("mixed with writes: got %v, want active", v)
	}
}

// A symbolic tag path (0x91 name) is how Logix addresses Read/Write
// Tag; the classifier must treat it as the tag namespace.
func TestClassifyCIPService_SymbolicTagPath(t *testing.T) {
	sym := EPathTarget{Symbol: "Motor_Speed", HasSymbol: true}
	if k, scoped := ClassifyCIPService(0x4D, sym); k != ServiceKindWrite || !scoped {
		t.Fatalf("write tag @ symbol: got %v scoped=%v, want write/true", k, scoped)
	}
	if k, scoped := ClassifyCIPService(0x4C, sym); k != ServiceKindRead || !scoped {
		t.Fatalf("read tag @ symbol: got %v scoped=%v, want read/true", k, scoped)
	}
}

func TestParseMRPath_SymbolSegment(t *testing.T) {
	// 0x91, len=3, "ABC", pad byte (odd length).
	path := []byte{0x91, 0x03, 'A', 'B', 'C', 0x00}
	got, err := ParseMRPath(path)
	if err != nil {
		t.Fatalf("ParseMRPath symbol: %v", err)
	}
	if !got.HasSymbol || got.Symbol != "ABC" {
		t.Fatalf("got symbol %q hasSymbol=%v, want ABC/true", got.Symbol, got.HasSymbol)
	}
}

// A Connected Data Item (0x00B1) carries a 2-byte sequence count
// before the MR request; ExtractMRService must skip it.
func TestExtractMRService_ConnectedDataItem(t *testing.T) {
	// MR: Get Attribute Single (0x0E), path class8=1 instance8=1.
	mr := []byte{0x0E, 0x02, 0x20, 0x01, 0x24, 0x01}
	itemData := append([]byte{0x01, 0x00}, mr...) // seq count + MR
	itemLen := byte(len(itemData))                //nolint:gosec // fixed small test payload
	item := []byte{0xB1, 0x00, itemLen, 0x00}
	item = append(item, itemData...)
	cpf := append([]byte{0x01, 0x00}, item...)             // ItemCount=1 + item
	body := append([]byte{0, 0, 0, 0, 0x0A, 0x00}, cpf...) // iface+timeout+cpf
	svc, tgt, ok := ExtractMRService(body)
	if !ok || svc != 0x0E || tgt.Class != 0x01 || tgt.Instance != 0x01 {
		t.Fatalf("connected MR: ok=%v svc=0x%02x class=%d inst=%d", ok, svc, tgt.Class, tgt.Instance)
	}
}
