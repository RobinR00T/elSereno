package cwmp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/cwmp"
)

func probeAgainst(t *testing.T, handler http.Handler) *core.Finding {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse httptest URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		t.Fatalf("parse host: %v", err)
	}

	p := cwmp.Default()
	p.Scheme = "http" // httptest.NewServer is plain HTTP
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 2 * time.Second

	portVal, err := core.NewPort(port)
	if err != nil {
		t.Fatalf("NewPort: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	f, err := p.Probe(ctx, core.Target{Address: addr, Port: portVal})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

// ---- Vendor matcher table tests -------------------------------

func TestIdentifyVendor_Table(t *testing.T) {
	cases := []struct {
		name   string
		header string
		body   string
		want   cwmp.Vendor
	}{
		{"genieacs-body", "", "GenieACS v1.2.8 ready", cwmp.VendorGenieACS},
		{"freeacs-header", "Server: FreeACS/1.1", "", cwmp.VendorFreeACS},
		{"axiros-header", "Server: AXACS 9.5", "", cwmp.VendorAxiros},
		{"nokia-body", "", "Nokia Altiplano Provisioning", cwmp.VendorNokia},
		{"huawei-body", "", "Huawei FusionHome Console", cwmp.VendorHuawei},
		{"broadcom-header", "Server: BroadWorks-ACS", "", cwmp.VendorBroadcom},
		{"cisco-body", "", "Cisco Prime provisioning", cwmp.VendorCisco},
		{"adb-body", "", "ADB TR069 Server", cwmp.VendorADB},
		{"friendly-body", "", "Friendly TR-069 Simulator", cwmp.VendorFriendlyT},
		{"tr069-generic", "", "TR-069 ACS ready", cwmp.VendorTR069Test},
		{"cwmp-generic", "", "cwmp endpoint", cwmp.VendorTR069Test},
		{"unknown-nginx", "Server: nginx/1.18", "welcome", cwmp.VendorUnknown},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := cwmp.IdentifyVendor(c.header, c.body)
			if got != c.want {
				t.Fatalf("IdentifyVendor(%q,%q) = %q, want %q", c.header, c.body, got, c.want)
			}
		})
	}
}

func TestVendorRisk_Tiers(t *testing.T) {
	cases := []struct {
		v    cwmp.Vendor
		risk int
	}{
		{cwmp.VendorGenieACS, 90},
		{cwmp.VendorFreeACS, 90},
		{cwmp.VendorOpenACS, 90},
		{cwmp.VendorAxiros, 85},
		{cwmp.VendorNokia, 85},
		{cwmp.VendorHuawei, 85},
		{cwmp.VendorBroadcom, 85},
		{cwmp.VendorCisco, 85},
		{cwmp.VendorFriendlyT, 75},
		{cwmp.VendorUnknown, 80},
		{cwmp.VendorTR069Test, 80},
	}
	for _, c := range cases {
		if got := cwmp.VendorRisk(c.v); got != c.risk {
			t.Errorf("VendorRisk(%q) = %d, want %d", c.v, got, c.risk)
		}
	}
}

// ---- Probe path -----------------------------------------------

func TestProbe_GenieACS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "GenieACS/1.2.8")
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<cwmp:Inform>...</cwmp:Inform>"))
	})
	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("GenieACS protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
	if f.Protocol != "cwmp" {
		t.Fatalf("Protocol = %q, want cwmp", f.Protocol)
	}
}

func TestProbe_NokiaAltiplano(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Nokia-Altiplano/3.5")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Altiplano Provisioning Console"))
	})
	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 85 {
		t.Fatalf("Nokia protocol_risk = %d, want 85", f.Factors["protocol_risk"])
	}
}

func TestProbe_401WithCWMPRealm(t *testing.T) {
	// No vendor string, but the Digest realm names the service.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Www-Authenticate", `Digest realm="acs-server", qop="auth", nonce="abc"`)
		w.WriteHeader(http.StatusUnauthorized) //nolint:misspell // RFC 7235 canonical spelling
	})
	f := probeAgainst(t, handler)
	// cwmp-likely heuristic should fire (realm contains "acs")
	// → protocol_risk 80, auth_state 50.
	if f.Factors["protocol_risk"] != 80 {
		t.Fatalf("cwmp-likely protocol_risk = %d, want 80", f.Factors["protocol_risk"])
	}
	if f.Factors["auth_state"] != 50 {
		t.Fatalf("cwmp 401 auth_state = %d, want 50", f.Factors["auth_state"])
	}
}

func TestProbe_SOAPFault(t *testing.T) {
	// SOAP fault body mentioning CWMP — ACS-likely.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<soap:Envelope><soap:Body><soap:Fault><faultstring>cwmp.InternalError</faultstring></soap:Fault></soap:Body></soap:Envelope>`))
	})
	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 80 {
		t.Fatalf("SOAP-fault cwmp protocol_risk = %d, want 80", f.Factors["protocol_risk"])
	}
}

func TestProbe_NonCWMPSite(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>nothing here</body></html>`))
	})
	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 30 {
		t.Fatalf("non-CWMP HTTP protocol_risk = %d, want 30", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 30 {
		t.Fatalf("non-CWMP HTTP capability = %d, want 30", f.Factors["capability"])
	}
}

// ---- metadata + proxy -----------------------------------------

func TestMetadata(t *testing.T) {
	md := cwmp.Default().Metadata()
	if md.Name != "cwmp" {
		t.Fatalf("Name=%q, want cwmp", md.Name)
	}
	if md.DefaultPort != 7547 {
		t.Fatalf("DefaultPort=%d, want 7547", md.DefaultPort)
	}
	if md.Build != "default" {
		t.Fatalf("Build=%q, want default", md.Build)
	}
}

func TestREPLUnsupported(t *testing.T) {
	if err := cwmp.Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("expected REPL unsupported error")
	}
}

func TestProxyHandler_DenyAll(t *testing.T) {
	p := cwmp.Default()
	h := p.ProxyHandler()
	if h == nil {
		t.Fatal("ProxyHandler returned nil")
	}
	var buf strings.Builder
	err := h.Handle(context.Background(), &pipeRW{w: &buf}, &pipeRW{w: &buf})
	if err == nil {
		t.Fatal("expected deny error")
	}
	if !strings.Contains(buf.String(), "403 Forbidden") { //nolint:misspell // RFC 7235 canonical spelling
		t.Fatalf("expected 403 Forbidden, got:\n%s", buf.String())
	}
}

type pipeRW struct{ w *strings.Builder }

func (p *pipeRW) Read(_ []byte) (int, error)  { return 0, nil }
func (p *pipeRW) Write(b []byte) (int, error) { return p.w.Write(b) }
