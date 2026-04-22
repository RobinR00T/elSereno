package pbxhttp_test

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
	"local/elsereno/internal/protocols/pbxhttp"
)

// probeAgainst spins up an httptest server (plain HTTP for
// simplicity — TLS is covered separately) and returns the
// finding produced by Default().Probe against it.
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

	p := pbxhttp.Default()
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

func TestProbe_FreePBXAdmin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Unix)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <title>FreePBX Administration</title>
</head>
<body>
  <h1>Welcome to FreePBX</h1>
  <form id="login">
    <input type="password" name="password"/>
  </form>
</body>
</html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("FreePBX protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 60 {
		t.Fatalf("FreePBX capability = %d, want 60", f.Factors["capability"])
	}
	if f.Protocol != "pbxhttp" {
		t.Fatalf("Protocol = %q, want pbxhttp", f.Protocol)
	}
}

func TestProbe_ThreeCXWebClient(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "3CX Phone System")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>3CX Web Client</title></head>
<body>3CX Phone System 18.0</body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("3CX protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
}

func TestProbe_CiscoUCMAdmin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "CiscoInet/1.1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Cisco Unified CM Administration</title></head>
<body><form action="/ccmadmin/login.do" method="post">...</form></body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 85 {
		t.Fatalf("Cisco UCM protocol_risk = %d, want 85", f.Factors["protocol_risk"])
	}
}

func TestProbe_Yeastar(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Yeastar P-Series</title></head>
<body>Linkus Server loading...</body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 80 {
		t.Fatalf("Yeastar protocol_risk = %d, want 80", f.Factors["protocol_risk"])
	}
}

func TestProbe_Grandstream(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "GS-HTTPD/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>UCM6302</title>
<body>Grandstream Networks, Inc.</body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 80 {
		t.Fatalf("Grandstream protocol_risk = %d, want 80", f.Factors["protocol_risk"])
	}
}

func TestProbe_NonPBXSite(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Welcome to nginx!</title></head>
<body>Company blog.</body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 30 {
		t.Fatalf("non-PBX HTTP protocol_risk = %d, want 30 (default)", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 30 {
		t.Fatalf("non-PBX HTTP capability = %d, want 30", f.Factors["capability"])
	}
}

func TestProbe_PBXLikelyHeuristic(t *testing.T) {
	// No vendor markers, but the body mentions "PBX" + extensions
	// → the heuristic fires and protocol_risk bumps to 70.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Bespoke/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Admin Console</title></head>
<body>Custom PBX management. Manage extensions here.</body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["protocol_risk"] != 70 {
		t.Fatalf("PBX-likely heuristic protocol_risk = %d, want 70", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 50 {
		t.Fatalf("PBX-likely heuristic capability = %d, want 50", f.Factors["capability"])
	}
}

func TestProbe_401DropsAuthState(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Asterisk/18.4.0")
		w.Header().Set("Www-Authenticate", `Digest realm="asterisk"`)
		w.WriteHeader(http.StatusUnauthorized) //nolint:misspell // RFC 7235 canonical spelling
		_, _ = w.Write([]byte(`<html><body>401</body></html>`))
	})

	f := probeAgainst(t, handler)
	if f.Factors["auth_state"] != 50 {
		t.Fatalf("401 auth_state = %d, want 50", f.Factors["auth_state"])
	}
	if f.Factors["protocol_risk"] != 90 { // Asterisk
		t.Fatalf("Asterisk protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
}

func TestProbe_TLSSelfSigned(t *testing.T) {
	// httptest.NewTLSServer ships a self-signed cert; ensure
	// InsecureSkipVerify = true (Default()) lets the probe
	// succeed anyway.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Apache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><title>FreePBX Administration</title></html>`))
	})
	srv := httptest.NewTLSServer(handler)
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	addr, _ := netip.ParseAddr(u.Hostname())

	p := pbxhttp.Default() // Scheme = "https", InsecureSkipVerify = true
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 2 * time.Second

	portVal, _ := core.NewPort(port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, err := p.Probe(ctx, core.Target{Address: addr, Port: portVal})
	if err != nil {
		t.Fatalf("Probe (TLS self-signed): %v", err)
	}
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("TLS FreePBX protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
}

func TestMetadata(t *testing.T) {
	md := pbxhttp.Default().Metadata()
	if md.Name != "pbxhttp" {
		t.Fatalf("Name=%q, want pbxhttp", md.Name)
	}
	if md.DefaultPort != 443 {
		t.Fatalf("DefaultPort=%d, want 443", md.DefaultPort)
	}
	if md.Build != "default" {
		t.Fatalf("Build=%q, want default", md.Build)
	}
}

func TestREPLUnsupported(t *testing.T) {
	err := pbxhttp.Default().REPL(context.Background(), nil)
	if err == nil {
		t.Fatal("expected REPL unsupported error")
	}
}

func TestProxyHandler_DenyAll(t *testing.T) {
	p := pbxhttp.Default()
	h := p.ProxyHandler()
	if h == nil {
		t.Fatal("ProxyHandler returned nil")
	}
	var buf strings.Builder
	err := h.Handle(context.Background(), &pipeRW{w: &buf}, &pipeRW{w: &buf})
	if err == nil {
		t.Fatal("expected deny error from default proxy")
	}
	if !strings.Contains(buf.String(), "403 Forbidden") { //nolint:misspell // RFC 7235 canonical spelling
		t.Fatalf("expected 403 Forbidden in reply, got:\n%s", buf.String())
	}
}

// pipeRW adapts a strings.Builder to io.ReadWriter for the proxy
// deny-handler test. Reads are never expected.
type pipeRW struct{ w *strings.Builder }

func (p *pipeRW) Read(_ []byte) (int, error)  { return 0, nil }
func (p *pipeRW) Write(b []byte) (int, error) { return p.w.Write(b) }

func TestIdentifyVendor_Table(t *testing.T) {
	cases := []struct {
		name                string
		header, title, body string
		want                pbxhttp.Vendor
	}{
		{"freepbx-title", "", "FreePBX Administration", "", pbxhttp.VendorFreePBX},
		{"freepbx-body", "", "", "welcome to freepbx", pbxhttp.VendorFreePBX},
		{"pbxact", "", "sangoma pbxact", "", pbxhttp.VendorPBXact},
		{"3cx", "", "", "3cx phone system 18", pbxhttp.VendorThreeCX},
		{"yeastar", "", "yeastar p-series", "", pbxhttp.VendorYeastar},
		{"ciscoucm", "", "cisco unified cm administration", "", pbxhttp.VendorCiscoUCM},
		{"avaya", "", "", "avaya aura communication manager", pbxhttp.VendorAvaya},
		{"mitel", "", "micollab", "", pbxhttp.VendorMitel},
		{"grandstream", "", "", "grandstream networks", pbxhttp.VendorGrandstream},
		{"fanvil", "server: fanvil-http/1.0", "", "", pbxhttp.VendorFanvil},
		{"yealink", "", "yealink sip-t46s", "", pbxhttp.VendorYealink},
		{"asterisk-header", "server: asterisk/18.4.0", "", "", pbxhttp.VendorAsterisk},
		{"switchvox", "", "", "switchvox login", pbxhttp.VendorSwitchvox},
		{"elastix", "", "elastix pbx", "", pbxhttp.VendorElastix},
		{"freeswitch", "", "", "freeswitch mod_xml_rpc", pbxhttp.VendorFreeSWITCH},
		{"unknown", "", "welcome", "generic login", pbxhttp.VendorUnknown},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pbxhttp.IdentifyVendor(c.header, c.title, c.body)
			if got != c.want {
				t.Fatalf("IdentifyVendor(%q,%q,%q) = %q, want %q", c.header, c.title, c.body, got, c.want)
			}
		})
	}
}

func TestVendorRisk_Tiers(t *testing.T) {
	type pair struct {
		v    pbxhttp.Vendor
		risk int
	}
	// Sanity-check each vendor maps to the documented tier.
	cases := []pair{
		{pbxhttp.VendorFreePBX, 90},
		{pbxhttp.VendorThreeCX, 90},
		{pbxhttp.VendorAsterisk, 90},
		{pbxhttp.VendorPBXact, 90},
		{pbxhttp.VendorElastix, 90},
		{pbxhttp.VendorCiscoUCM, 85},
		{pbxhttp.VendorAvaya, 85},
		{pbxhttp.VendorMitel, 85},
		{pbxhttp.VendorYeastar, 80},
		{pbxhttp.VendorGrandstream, 80},
		{pbxhttp.VendorFanvil, 80},
		{pbxhttp.VendorYealink, 80},
		{pbxhttp.VendorSwitchvox, 75},
		{pbxhttp.VendorFreeSWITCH, 75},
		{pbxhttp.VendorUnknown, 70},
	}
	for _, c := range cases {
		if got := pbxhttp.VendorRisk(c.v); got != c.risk {
			t.Errorf("VendorRisk(%q) = %d, want %d", c.v, got, c.risk)
		}
	}
}
