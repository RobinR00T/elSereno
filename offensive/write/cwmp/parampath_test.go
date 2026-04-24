//go:build offensive

package cwmp_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
)

// ---- AllowlistHashWithParameterPaths --------------------------

func TestAllowlistHashWithParameterPaths_EmptyMatchesV11(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	h11 := cwmpwrite.AllowlistHash("acs:7547", rpcs)
	h12 := cwmpwrite.AllowlistHashWithParameterPaths("acs:7547", rpcs, nil)
	if !hashEqual(h11, h12) {
		t.Fatalf("v1.12 hash with empty paths differs from v1.11: %x vs %x", h12, h11)
	}
}

func TestAllowlistHashWithParameterPaths_Changes(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	paths := []cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice.WANDevice."}}
	h11 := cwmpwrite.AllowlistHash("acs:7547", rpcs)
	h12 := cwmpwrite.AllowlistHashWithParameterPaths("acs:7547", rpcs, paths)
	if hashEqual(h11, h12) {
		t.Fatal("v1.12 hash with paths must differ from v1.11")
	}
}

func TestAllowlistHashWithParameterPaths_OrderInsensitive(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	a := []cwmpwrite.AllowedParameterPath{
		{Prefix: "InternetGatewayDevice.WANDevice."},
		{Prefix: "InternetGatewayDevice.LANDevice."},
	}
	b := []cwmpwrite.AllowedParameterPath{
		{Prefix: "InternetGatewayDevice.LANDevice."},
		{Prefix: "InternetGatewayDevice.WANDevice."},
	}
	ha := cwmpwrite.AllowlistHashWithParameterPaths("t", rpcs, a)
	hb := cwmpwrite.AllowlistHashWithParameterPaths("t", rpcs, b)
	if !hashEqual(ha, hb) {
		t.Fatal("hash depends on path input order")
	}
}

func TestAllowlistHashWithParameterPaths_CaseSensitive(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	a := []cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice."}}
	b := []cwmpwrite.AllowedParameterPath{{Prefix: "internetgatewaydevice."}}
	if hashEqual(
		cwmpwrite.AllowlistHashWithParameterPaths("t", rpcs, a),
		cwmpwrite.AllowlistHashWithParameterPaths("t", rpcs, b),
	) {
		t.Fatal("hash must distinguish case (TR-069 data-model names are case-sensitive)")
	}
}

func TestAllowlistHashWithParameterPaths_WhitespaceTrimmed(t *testing.T) {
	rpcs := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	a := []cwmpwrite.AllowedParameterPath{{Prefix: "  InternetGatewayDevice.  "}}
	b := []cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice."}}
	if !hashEqual(
		cwmpwrite.AllowlistHashWithParameterPaths("t", rpcs, a),
		cwmpwrite.AllowlistHashWithParameterPaths("t", rpcs, b),
	) {
		t.Fatal("path canonicaliser should trim whitespace")
	}
}

// ---- End-to-end gate with per-path allowlist active -----------

// driveSessionWithPaths wires a WriteGatedHandler with both the
// v1.11 RPC list AND the v1.12 per-parameter-path list.
func driveSessionWithPaths(t *testing.T, rpcs []cwmpwrite.AllowedRPC, paths []cwmpwrite.AllowedParameterPath) (net.Conn, *upstreamACS) {
	t.Helper()
	target := "acs.test:7547"
	h := &cwmpwrite.WriteGatedHandler{
		Target:                target,
		Allowed:               rpcs,
		AllowedParameterPaths: paths,
		Deriver:               &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:               &fakeAuditor{},
	}
	mut := cwmpwrite.SessionMutationWithParameterPaths(target, rpcs, paths)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	h.SessionConfirm = confirm.Confirm{
		AcceptsWrites: true,
		ConfirmTarget: target,
		ConfirmToken:  tok,
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientPipe, handlerClientSide := net.Pipe()
	handlerUpstreamSide, originSide := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = originSide.Close()
	})

	acs := &upstreamACS{}
	go acs.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientPipe, acs
}

// setParamValuesBody builds a SetParameterValues SOAP envelope
// with one or more parameter names.
func setParamValuesBody(names ...string) string {
	var params strings.Builder
	for _, n := range names {
		fmt.Fprintf(&params,
			`<ParameterValueStruct><Name>%s</Name><Value xsi:type="xsd:string">v</Value></ParameterValueStruct>`,
			n)
	}
	return soapEnvelope(fmt.Sprintf(
		`<cwmp:SetParameterValues><ParameterList>%s</ParameterList><ParameterKey>k</ParameterKey></cwmp:SetParameterValues>`,
		params.String()))
}

// TestGatePerPath_AllowedPathPasses — single parameter under an
// allowed prefix → PASS.
func TestGatePerPath_AllowedPathPasses(t *testing.T) {
	client, acs := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}},
		[]cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice.WANDevice."}},
	)
	body := setParamValuesBody("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress")
	_, _ = io.WriteString(client, postRequest(body))
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("allowed path: got %d, want 200", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := acs.seen(); n != 1 {
		t.Fatalf("ACS saw %d requests, want 1", n)
	}
}

// TestGatePerPath_UnknownPathRefused — parameter outside the
// allowed prefixes → SOAP Fault 9005 (Invalid parameter name).
func TestGatePerPath_UnknownPathRefused(t *testing.T) {
	client, acs := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}},
		[]cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice.WANDevice."}},
	)
	// Operator-safe WAN prefix, but attacker tries to push a
	// LAN-side config change.
	body := setParamValuesBody("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.LANIPInterface.1.IPAddress")
	_, _ = io.WriteString(client, postRequest(body))
	code, header, respBody := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("blocked path: got %d, want 200 (TR-069 app-level Fault)", code)
	}
	if !strings.Contains(respBody, "9005") {
		t.Errorf("refusal should carry FaultCode 9005:\n%s", respBody)
	}
	reason := header.Get("X-Elsereno-Gate-Reason")
	if !strings.Contains(reason, "parameter path") {
		t.Errorf("X-Elsereno-Gate-Reason doesn't mention path gate: %q", reason)
	}
	time.Sleep(50 * time.Millisecond)
	if _, n := acs.seen(); n != 0 {
		t.Fatalf("ACS saw %d requests for a blocked path, want 0", n)
	}
}

// TestGatePerPath_MixedNamesOneOutsideRefused — when EVEN ONE
// of the parameters in the request is outside the allowlist,
// the entire RPC is refused. Prevents an attacker slipping a
// malicious setting inside a batch of benign ones.
func TestGatePerPath_MixedNamesOneOutsideRefused(t *testing.T) {
	client, _ := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}},
		[]cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice.WANDevice."}},
	)
	body := setParamValuesBody(
		"InternetGatewayDevice.WANDevice.1.X_ENABLED",                    // OK
		"InternetGatewayDevice.LANDevice.1.X_ROOT_PASSWORD",              // BAD
		"InternetGatewayDevice.WANDevice.2.WANConnectionDevice.1.X_ADDR", // OK
	)
	_, _ = io.WriteString(client, postRequest(body))
	_, _, respBody := readHTTPResponseSummary(t, client)
	if !strings.Contains(respBody, "9005") {
		t.Errorf("mixed-name batch: one bad should refuse the whole RPC:\n%s", respBody)
	}
}

// TestGatePerPath_EmptyPathListFallsBackToV11 — empty path list
// degrades to v1.11 behaviour: RPC-only gating, any parameter
// target accepted.
func TestGatePerPath_EmptyPathListFallsBackToV11(t *testing.T) {
	client, acs := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}},
		nil, // no per-path gating
	)
	body := setParamValuesBody("InternetGatewayDevice.AnywhereYouWant.X")
	_, _ = io.WriteString(client, postRequest(body))
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("empty path list fallback: got %d, want 200", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := acs.seen(); n != 1 {
		t.Fatalf("ACS saw %d requests, want 1 (empty path list = RPC-only gate)", n)
	}
}

// TestGatePerPath_RebootNotAffectedByPathAllowlist — the per-
// path gate only applies to Set* RPCs. Reboot with an active
// path allowlist should still be gated purely by the RPC list.
func TestGatePerPath_RebootNotAffectedByPathAllowlist(t *testing.T) {
	client, acs := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "Reboot"}},
		[]cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice.WANDevice."}},
	)
	body := soapEnvelope(`<cwmp:Reboot><CommandKey>test</CommandKey></cwmp:Reboot>`)
	_, _ = io.WriteString(client, postRequest(body))
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("Reboot with path-gate active: got %d, want 200 (path gate applies to Set* only)", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := acs.seen(); n != 1 {
		t.Fatalf("ACS saw %d requests, want 1 (Reboot not affected by path gate)", n)
	}
}

// TestGatePerPath_EmptySetParameterValuesBodyRefused — fail-
// closed behaviour: a SetParameterValues with no parameter
// names in it is refused when the per-path gate is active
// (attacker can't slip through by sending empty requests).
func TestGatePerPath_EmptySetParameterValuesBodyRefused(t *testing.T) {
	client, acs := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}},
		[]cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice."}},
	)
	// No ParameterValueStruct at all (malformed per TR-069 but
	// the gate shouldn't pass it).
	body := soapEnvelope(`<cwmp:SetParameterValues><ParameterList></ParameterList><ParameterKey>k</ParameterKey></cwmp:SetParameterValues>`)
	_, _ = io.WriteString(client, postRequest(body))
	_, _, respBody := readHTTPResponseSummary(t, client)
	if !strings.Contains(respBody, "9005") {
		t.Errorf("empty Set* body: fail-closed should produce SOAP Fault 9005:\n%s", respBody)
	}
	time.Sleep(50 * time.Millisecond)
	if _, n := acs.seen(); n != 0 {
		t.Fatalf("ACS saw %d requests for a zero-param Set*, want 0", n)
	}
}

// TestGatePerPath_SetParameterAttributesAlsoGated — the same
// path gate applies to SetParameterAttributes (different inner
// struct but same Name element).
func TestGatePerPath_SetParameterAttributesAlsoGated(t *testing.T) {
	client, _ := driveSessionWithPaths(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterAttributes"}},
		[]cwmpwrite.AllowedParameterPath{{Prefix: "InternetGatewayDevice.WANDevice."}},
	)
	body := soapEnvelope(`<cwmp:SetParameterAttributes><ParameterList><SetParameterAttributesStruct><Name>InternetGatewayDevice.LANDevice.X</Name><NotificationChange>1</NotificationChange><Notification>2</Notification><AccessListChange>0</AccessListChange><AccessList/></SetParameterAttributesStruct></ParameterList></cwmp:SetParameterAttributes>`)
	_, _ = io.WriteString(client, postRequest(body))
	_, _, respBody := readHTTPResponseSummary(t, client)
	if !strings.Contains(respBody, "9005") {
		t.Errorf("SetParameterAttributes: path gate should also fire:\n%s", respBody)
	}
}
