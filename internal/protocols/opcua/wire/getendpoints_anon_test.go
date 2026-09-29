package wire_test

import (
	"os"
	"testing"

	"local/elsereno/internal/protocols/opcua/wire"
)

// TestDecodeGetEndpoints_AnonymousPolicyID validates the anonymous
// PolicyId extraction against a REAL captured GetEndpointsResponse (the
// SecurityPolicy#None session from ITI/ICS-Security-Tools; body from the
// message TypeId onward). The server advertised an Anonymous
// UserTokenPolicy with PolicyId "0".
func TestDecodeGetEndpoints_AnonymousPolicyID(t *testing.T) {
	body, err := os.ReadFile("testdata/getendpoints_resp_none.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	eps, err := wire.DecodeGetEndpointsResponse(body)
	if err != nil {
		t.Fatalf("DecodeGetEndpointsResponse: %v", err)
	}
	if len(eps) == 0 {
		t.Fatal("no endpoints decoded from the real capture")
	}
	var anon *wire.EndpointDescription
	for i := range eps {
		if eps[i].AllowsAnonymous {
			anon = &eps[i]
			break
		}
	}
	if anon == nil {
		t.Fatal("no endpoint advertised anonymous access in the real capture")
	}
	if anon.AnonymousPolicyID != "0" {
		t.Fatalf("AnonymousPolicyID = %q, want %q", anon.AnonymousPolicyID, "0")
	}
	if anon.SecurityMode != wire.SecurityModeNone {
		t.Errorf("expected the anonymous endpoint to be SecurityMode=None, got %d", anon.SecurityMode)
	}
}
