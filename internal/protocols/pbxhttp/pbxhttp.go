package pbxhttp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"local/elsereno/internal/core"
)

// Name is the plugin identifier.
const Name = "pbxhttp"

// DefaultPort is the most common PBX admin-UI port (HTTPS). The
// plugin also works against 80 / 8080 / 8088 / 5001 / 7443 / 411
// when the caller overrides Scheme + target.Port.
const DefaultPort core.Port = 443

// MaxBodyBytes caps how many bytes of the response body the probe
// reads before scanning for vendor markers. 16 KiB is enough for
// the <head> of nearly every PBX admin-login page.
const MaxBodyBytes int64 = 16 * 1024

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	// Scheme is "http" or "https". Default "https" (443 is the
	// most common PBX admin port, and self-signed certificates
	// are ubiquitous).
	Scheme string
	// Path is the URL path to GET. Default "/" — enough to
	// fingerprint most PBXes because the brand usually appears in
	// the HTML <title> or a canonical meta tag. Callers can
	// override to a vendor-specific path like "/admin/config.php"
	// when they already suspect FreePBX.
	Path string
	// UserAgent is the HTTP User-Agent header. Defaults to a
	// browser-looking string because some PBX login pages
	// actively block curl/go-http-client.
	UserAgent string
	// InsecureSkipVerify disables TLS certificate validation.
	// Default true — PBX default installs virtually always have
	// self-signed or long-expired certs, and we're fingerprinting
	// rather than talking to them, so the operational value
	// outweighs the MITM risk in this narrow context.
	InsecureSkipVerify bool
}

// Default returns a Plugin with sensible defaults for external
// scans: HTTPS, path "/", self-signed-cert tolerant.
func Default() *Plugin {
	return &Plugin{
		DialTimeout:        3 * time.Second,
		IOTimeout:          4 * time.Second,
		Scheme:             "https",
		Path:               "/",
		UserAgent:          "ElSereno-pbxhttp/1 (+https://github.com/RobinR00T/elSereno)",
		InsecureSkipVerify: true,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "HTTP(S) PBX admin-page fingerprint — identifies FreePBX, 3CX, Yeastar, Cisco UCM, Avaya, Mitel, Grandstream, Fanvil, Yealink, Asterisk Manager, Switchvox, Elastix, FreeSWITCH on ports 443 / 80 / 8088 / 5001 / 8443",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Issues one GET request to
// Scheme://target:port/Path, reads up to MaxBodyBytes of the
// response, and classifies by vendor markers in headers + title
// + body text.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	client := p.httpClient()

	scheme := p.Scheme
	if scheme == "" {
		scheme = "https"
	}
	path := p.Path
	if path == "" {
		path = "/"
	}
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	u := scheme + "://" + addr + path

	reqCtx, cancel := context.WithTimeout(ctx, p.DialTimeout+p.IOTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("pbxhttp: build request: %w", err)
	}
	ua := p.UserAgent
	if ua == "" {
		ua = "ElSereno-pbxhttp/1"
	}
	req.Header.Set("User-Agent", ua)
	// Pretend to accept HTML so PBX logins return their real
	// pages rather than JSON error bodies.
	req.Header.Set("Accept", "text/html, application/xhtml+xml, */*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pbxhttp: GET %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("pbxhttp: read body: %w", err)
	}

	headers := flattenHeaders(resp.Header)
	title := extractTitle(body)
	bodyLower := strings.ToLower(string(body))
	vendor := IdentifyVendor(headers, title, bodyLower)

	return buildFinding(target, resp.StatusCode, vendor, title, bodyLower), nil
}

// httpClient constructs an http.Client that observes DialTimeout,
// skips cert verification when configured, and refuses redirects
// (we want the first response, not a hop to a chained login URL
// that might be on a different vendor's portal).
func (p *Plugin) httpClient() *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: p.DialTimeout}).DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.InsecureSkipVerify, // #nosec G402 — PBX admin panels ubiquitously ship self-signed certs; we're fingerprinting, not transmitting credentials, so the operational value outweighs MITM risk in this narrow context.
			MinVersion:         tls.VersionTLS12,
		},
		TLSHandshakeTimeout: p.DialTimeout,
		// PBX admin pages are small — no need for keep-alive.
		DisableKeepAlives: true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   p.DialTimeout + p.IOTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// REPL stub — consistent with every other protocol plugin.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("pbxhttp: REPL arrives with the generic framework")
}

// ProxyHandler returns the default deny-all proxy. PBX admin UIs
// are login-gated but highly sensitive (config changes, SIP
// extension passwords, call-flow routing). The default build
// refuses every client byte with a 403. An offensive write-gated
// variant is a v1.4 candidate.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

// Handle writes an HTTP 403 and returns. Real HTTP clients parse
// the canonical status line correctly.
func (denyAll) Handle(_ context.Context, client, _ io.ReadWriter) error {
	_, _ = client.Write([]byte(
		"HTTP/1.1 403 Forbidden\r\n" +
			"Server: ElSereno proxy (read-only)\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n" +
			"\r\n",
	))
	return fmt.Errorf("pbxhttp: proxy refuses client input by default (offensive v1.4 adds the gated proxy)")
}

// flattenHeaders concatenates the headers we care about for
// fingerprinting into one inspectable string. Order is stable so
// the haystack is deterministic.
func flattenHeaders(h http.Header) string {
	var b strings.Builder
	for _, k := range []string{"Server", "X-Powered-By", "Www-Authenticate", "Set-Cookie"} {
		if v := h.Get(k); v != "" {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\n")
		}
	}
	return b.String()
}

// titleRE extracts the contents of the first <title>…</title>
// tag. Case-insensitive; stops at the first </title> close.
var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// extractTitle returns the HTML document title, or an empty
// string when no <title> tag is present. Bytes are preserved
// raw; the caller should lowercase before matching.
func extractTitle(body []byte) string {
	m := titleRE.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// buildFinding renders a scored finding from the HTTP response
// classification.
func buildFinding(target core.Target, statusCode int, vendor Vendor, title, bodyLower string) *core.Finding {
	matched := vendor != VendorUnknown

	// Additional heuristic: even if the vendor didn't match the
	// name list, a login form on the page + a PBX-ish path or
	// title ("PBX", "phone system", "SIP", "extension") nudges
	// protocol_risk to 70 so the finding still surfaces.
	pbxLikely := matched
	if !matched {
		for _, needle := range []string{"pbx", "phone system", "sip server", "voip admin", "extension"} {
			if strings.Contains(bodyLower, needle) || strings.Contains(strings.ToLower(title), needle) {
				pbxLikely = true
				break
			}
		}
	}

	factors := map[string]int{
		"protocol_risk": 30, // default for "HTTP responder, no PBX markers"
		"exposure":      70, // HTTP admin UIs on the public internet
		"auth_state":    60, // unknown — most PBX logins challenge but allow OPTIONS to pass
		"capability":    30,
		"impact_class":  40, // HTTP alone isn't a full PBX — scoring bumps on vendor match
		"cve_exposure":  0,
	}
	note := "non-pbx-http"
	if pbxLikely {
		note = "pbx-http-likely"
		factors["protocol_risk"] = 70
		factors["capability"] = 50
		factors["impact_class"] = 75
	}
	if matched {
		note = "pbx-http-" + string(vendor)
		factors["protocol_risk"] = VendorRisk(vendor)
		factors["capability"] = 60
		factors["impact_class"] = 80
	}

	// A 401 or 403 response is positive confirmation that auth
	// is enforced; drop auth_state a notch so scoring nudges
	// operators toward investigating credential strength. A 200
	// OK on an admin path is worse (either no auth or session
	// leaked), so keep auth_state at the default 60.
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden { //nolint:misspell // RFC 7235 §3.1 canonical spelling of net/http constants
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
