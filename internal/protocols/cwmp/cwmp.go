package cwmp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"local/elsereno/internal/core"
)

// Name is the plugin identifier.
const Name = "cwmp"

// DefaultPort is the TR-069 / CWMP ACS port. Some deployments
// also listen on 7548 (CWMP-TLS) and 30005; the plugin's Scheme
// field toggles TLS but the port stays configurable at the
// target level.
const DefaultPort core.Port = 7547

// MaxBodyBytes caps how many bytes of the ACS response the probe
// reads before scanning for vendor / fault markers. 16 KiB is
// more than enough for a SOAP fault body; ACS "you're not
// authenticated" pages are usually under 2 KiB.
const MaxBodyBytes int64 = 16 * 1024

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	// Scheme is "http" (default — TR-069 is historically plain
	// HTTP with Digest auth) or "https" for the less-common
	// CWMP-over-TLS deployments on 7548.
	Scheme string
	// UserAgent is the HTTP User-Agent header. TR-069 CPEs
	// typically identify themselves with a vendor-specific
	// string; we send "ElSereno-cwmp/1" so ACSs that
	// block-unknown-UAs fail open for us (which is the
	// fingerprinting intent).
	UserAgent string
	// InsecureSkipVerify disables TLS cert validation for the
	// https path. TR-069 ACSs on 7548 with self-signed certs are
	// common; we prefer identification over strict TLS here.
	InsecureSkipVerify bool
}

// Default returns a Plugin with sensible defaults.
func Default() *Plugin {
	return &Plugin{
		DialTimeout:        3 * time.Second,
		IOTimeout:          4 * time.Second,
		Scheme:             "http",
		UserAgent:          "ElSereno-cwmp/1 (+https://github.com/RobinR00T/elSereno)",
		InsecureSkipVerify: true,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "TR-069 / CWMP ACS fingerprint on 7547 — identifies GenieACS, FreeACS, Axiros, Nokia Altiplano, Huawei FusionHome, Broadcom BroadWorks, Cisco Prime, ADB, and generic CWMP ACS responders",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends an HTTP GET to the root
// path of the ACS, captures the Server / WWW-Authenticate headers
// + any response body, and classifies by vendor.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	client := p.httpClient()

	scheme := p.Scheme
	if scheme == "" {
		scheme = "http"
	}
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	u := scheme + "://" + addr + "/"

	reqCtx, cancel := context.WithTimeout(ctx, p.DialTimeout+p.IOTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("cwmp: build request: %w", err)
	}
	ua := p.UserAgent
	if ua == "" {
		ua = "ElSereno-cwmp/1"
	}
	req.Header.Set("User-Agent", ua)
	// Hint that we speak SOAP — some ACSs gate the 401 challenge
	// on SOAPAction presence.
	req.Header.Set("SOAPAction", "")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cwmp: GET %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("cwmp: read body: %w", err)
	}
	headers := flattenHeaders(resp.Header)
	vendor := IdentifyVendor(headers, string(body))
	cwmpLikely := vendor != VendorUnknown || isCWMPLikely(resp.StatusCode, headers, string(body))

	return buildFinding(target, resp.StatusCode, vendor, cwmpLikely), nil
}

// httpClient builds the HTTP client with the plugin's timeouts
// and TLS preferences.
func (p *Plugin) httpClient() *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: p.DialTimeout}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.InsecureSkipVerify, // #nosec G402 — CWMP ACS on 7548 ubiquitously ships self-signed; we're fingerprinting, not transmitting credentials.
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout: p.DialTimeout,
		DisableKeepAlives:   true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   p.DialTimeout + p.IOTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("cwmp: REPL arrives with the generic framework")
}

// ProxyHandler returns the default deny-all proxy. An ACS proxy
// is extremely sensitive — any write to the gate could push
// config to a fleet. The default build refuses every client
// byte; an offensive write-gated variant (v1.5+) would
// allowlist specific SOAP RPCs (GetParameterValues for reads,
// explicit SetParameterValues for writes).
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

// Handle writes a plain HTTP 403 + closes the connection.
func (denyAll) Handle(_ context.Context, client, _ io.ReadWriter) error {
	_, _ = client.Write([]byte(
		"HTTP/1.1 403 Forbidden\r\n" +
			"Server: ElSereno proxy (read-only)\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n\r\n",
	))
	return fmt.Errorf("cwmp: proxy refuses client input by default (offensive v1.5 adds the gated proxy)")
}

// flattenHeaders concatenates the HTTP headers most useful for
// CWMP fingerprinting into one inspectable string.
func flattenHeaders(h http.Header) string {
	var b strings.Builder
	for _, k := range []string{"Server", "Www-Authenticate", "Content-Type", "X-Powered-By", "Set-Cookie"} {
		if v := h.Get(k); v != "" {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// isCWMPLikely applies heuristics for "this responder is
// probably an ACS even though no vendor string matched".
// Signals:
//
//   - 401 challenge with realm containing "acs" or "cwmp"
//   - Content-Type text/xml with "soap" or "cwmp" in the body
//   - Server header on port 7547 of any shape (just being on
//     the well-known CWMP port is already weak evidence, but we
//     don't want to falsely fingerprint unrelated HTTP servers
//     that happen to listen on 7547)
func isCWMPLikely(statusCode int, headers, body string) bool {
	lower := strings.ToLower(headers + "\n" + body)
	if statusCode == http.StatusUnauthorized && //nolint:misspell // RFC 7235 canonical spelling
		(strings.Contains(lower, "acs") || strings.Contains(lower, "cwmp") || strings.Contains(lower, "tr-069") || strings.Contains(lower, "tr069")) {
		return true
	}
	if strings.Contains(lower, "soap") && strings.Contains(lower, "cwmp") {
		return true
	}
	return false
}

// buildFinding scores the CWMP finding.
func buildFinding(target core.Target, statusCode int, vendor Vendor, cwmpLikely bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 30, // default for "HTTP responder, not obviously CWMP"
		"exposure":      80, // 7547 on the public internet is a finding — fleet-wide
		"auth_state":    60,
		"capability":    30,
		"impact_class":  50, // HTTP alone isn't catastrophic without CWMP confirmation
		"cve_exposure":  0,
	}
	note := "non-cwmp-http"
	if cwmpLikely {
		note = "cwmp-likely"
		factors["protocol_risk"] = 80
		factors["capability"] = 60
		factors["impact_class"] = 85 // exposed ACS → fleet compromise
	}
	if vendor != VendorUnknown {
		note = "cwmp-" + string(vendor)
		factors["protocol_risk"] = VendorRisk(vendor)
		factors["capability"] = 60
		factors["impact_class"] = 90
	}
	// 401 with a CWMP realm → auth is enforced; drop auth_state
	// so the scorer nudges operators toward credential review.
	if statusCode == http.StatusUnauthorized { //nolint:misspell // RFC 7235 canonical spelling
		factors["auth_state"] = 50
	}
	score := scoreFor(factors)

	return &core.Finding{
		ID:          hashID(target, note, string(vendor)),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, note, string(vendor)),
	}
}

func scoreFor(factors map[string]int) int {
	weights := map[string]float64{
		"protocol_risk": 0.25, "exposure": 0.20, "auth_state": 0.20,
		"capability": 0.15, "impact_class": 0.10, "cve_exposure": 0.10,
	}
	var total float64
	for k, w := range weights {
		total += float64(factors[k]) * w
	}
	n := int(total + 0.5)
	if n < 0 {
		n = 0
	}
	if n > 100 {
		n = 100
	}
	return n
}

func portBytes(p core.Port) [2]byte {
	return [2]byte{byte(uint16(p) >> 8 & 0xff), byte(uint16(p) & 0xff)}
}

func hashID(target core.Target, note, vendor string) core.UUID {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte(note))
	_, _ = h.Write([]byte(vendor))
	return core.UUID(hex.EncodeToString(h.Sum(nil)[:16]))
}

func hashBytes(target core.Target, note, vendor string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte(note))
	_, _ = h.Write([]byte(vendor))
	return h.Sum(nil)
}
