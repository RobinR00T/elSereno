package opcuahttps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/render"
)

// Name is the plugin identifier.
const Name = "opcuahttps"

// DefaultPort is 4843 (registered for opc.https / opc.wss per
// OPC UA Part 6). Operators can re-target 443 for misconfigured
// SCADA gateways exposing OPC UA on the standard HTTPS port.
const DefaultPort core.Port = 4843

// discoveryPath is the OPC UA HTTPS discovery endpoint per spec.
const discoveryPath = "/discovery"

// uaBinaryContentType is the Content-Type for OPC UA over
// HTTPS in binary encoding.
const uaBinaryContentType = "application/opcua+uabinary"

// uaJSONContentType is the OPC UA HTTPS JSON encoding type.
const uaJSONContentType = "application/opcua+uajson"

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	// SkipVerify lets the plugin probe self-signed SCADA certs,
	// which are the dominant deployment pattern. Defaults to
	// true (defensive fingerprint; we're not establishing trust).
	SkipVerify bool
}

// Default returns a Plugin with sensible timeouts. SkipVerify
// defaults to true because OPC UA HTTPS deployments
// overwhelmingly use self-signed certs (the spec actually
// blesses this for in-network use).
func Default() *Plugin {
	return &Plugin{
		DialTimeout: 5 * time.Second,
		IOTimeout:   5 * time.Second,
		SkipVerify:  true,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "OPC UA HTTPS (Part 6 binding) fingerprint on 4843 — POST /discovery, classifies response Content-Type + Server header",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Performs a TLS handshake +
// HTTP POST /discovery with a synthetic 1-byte body (OPC UA
// servers return a non-200 protocol error but include the
// distinguishing headers we want). Inspects response headers
// to classify the strength of the UA fingerprint.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	// We do NOT verify the cert — see SkipVerify rationale on
	// the Plugin struct. The fingerprint cares about the
	// service identity (headers), not PKI trust.
	tlsCfg := &tls.Config{InsecureSkipVerify: p.SkipVerify, MinVersion: tls.VersionTLS12} // #nosec G402 — fingerprint-only; documented invariant.
	dialer := &net.Dialer{Timeout: p.DialTimeout}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsCfg}
	conn, err := tlsDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("opcuahttps: tls dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	// Single-shot HTTP/1.1 POST with the minimal-valid
	// payload. We could craft a real GetEndpointsRequest in
	// UA binary but that's overkill for fingerprinting; the
	// server's response headers alone suffice.
	req := buildDiscoveryRequest(target.Address.String())
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, fmt.Errorf("opcuahttps: write: %w", err)
	}
	respBytes, readErr := io.ReadAll(io.LimitReader(conn, 8192))
	if readErr != nil && !errors.Is(readErr, io.EOF) && !strings.Contains(readErr.Error(), "EOF") {
		return nil, fmt.Errorf("opcuahttps: read: %w", readErr)
	}
	if len(respBytes) == 0 {
		// Empty HTTPS response after TLS handshake — not OPC
		// UA but report the fact for forensic value.
		return buildFinding(target, "tls-handshake-only", false, "", ""), nil
	}
	return classifyResponse(target, respBytes), nil
}

// buildDiscoveryRequest assembles the HTTP/1.1 POST.
// Host header carries the target hostname so SNI-aware
// servers route correctly. Content-Length is 1 (a single
// 0x00 byte) — OPC UA servers usually respond with an HTTP
// 400/500 but still emit the diagnostic Server/Content-Type
// headers we need.
func buildDiscoveryRequest(host string) string {
	body := "\x00" // one-byte minimal body
	var b strings.Builder
	b.WriteString("POST " + discoveryPath + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("Content-Type: " + uaBinaryContentType + "\r\n")
	b.WriteString("Content-Length: 1\r\n")
	b.WriteString("User-Agent: elsereno-opcuahttps/1.0\r\n")
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// classifyResponse parses an HTTP response prefix from the
// first 8KB. We only need headers; body is incidental.
//
// Header parsing is intentionally minimal — we tolerate
// malformed responses (OPC UA servers occasionally emit
// non-RFC-compliant headers) by looking for substrings.
func classifyResponse(target core.Target, resp []byte) *core.Finding {
	// Split headers from body at the first \r\n\r\n.
	hdrEnd := bytes.Index(resp, []byte("\r\n\r\n"))
	headerBlock := resp
	if hdrEnd >= 0 {
		headerBlock = resp[:hdrEnd]
	}
	// Lowercase pass for case-insensitive matching.
	lower := strings.ToLower(string(headerBlock))

	hasUABinary := strings.Contains(lower, strings.ToLower(uaBinaryContentType))
	hasUAJSON := strings.Contains(lower, strings.ToLower(uaJSONContentType))
	hasUAServer := serverSuggestsUA(lower)
	statusLine := firstLine(headerBlock)

	// Score the hit:
	//   - UA binary content-type → strong (capability 80).
	//   - UA JSON content-type   → strong (capability 75).
	//   - Server header suggests UA → moderate (capability 60).
	//   - Plain HTTPS with no UA hints → not OPC UA (build no
	//     finding — return early).
	switch {
	case hasUABinary:
		return buildFinding(target, "uabinary-discovery", true, statusLine,
			extractServer(lower))
	case hasUAJSON:
		return buildFinding(target, "uajson-discovery", true, statusLine,
			extractServer(lower))
	case hasUAServer:
		return buildFinding(target, "ua-server-header", false, statusLine,
			extractServer(lower))
	default:
		// Plain HTTPS response that doesn't look like OPC UA.
		// We DON'T return a finding here — saves the operator
		// from noise. Plain HTTP plugins (banner / etc) cover
		// it.
		return nil
	}
}

// serverSuggestsUA matches a curated list of OPC UA stack
// names commonly observed in production. NOT exhaustive —
// new vendors get added as we observe them.
func serverSuggestsUA(lower string) bool {
	uaStacks := []string{
		"opc ua",
		"opcua",
		"uaexpert",
		"prosys",
		"unified automation",
		"ascolab",
		"matrikon",
		"kepware",
		"open62541",
		"node-opcua",
	}
	for _, needle := range uaStacks {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// extractServer pulls the Server header value, lowercase.
// Empty if not present.
func extractServer(lower string) string {
	idx := strings.Index(lower, "\r\nserver:")
	if idx < 0 {
		return ""
	}
	tail := lower[idx+len("\r\nserver:"):]
	end := strings.Index(tail, "\r\n")
	if end < 0 {
		end = len(tail)
	}
	return strings.TrimSpace(tail[:end])
}

// firstLine returns the HTTP status line (everything before
// the first \r\n). Capped at 200 chars to bound log noise.
func firstLine(b []byte) string {
	end := bytes.Index(b, []byte("\r\n"))
	if end < 0 {
		end = len(b)
	}
	if end > 200 {
		end = 200
	}
	return string(b[:end])
}

// buildFinding assembles the core.Finding. uaBinding=true means
// the headers showed a UA content-type explicitly; false means
// only a Server-header hint.
func buildFinding(target core.Target, note string, uaBinding bool, statusLine, serverHdr string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 65, // OPC UA HTTPS handles auth via cert/userid; less
		// commonly exploited than opc.tcp but still operational impact when wrong.
		"exposure":     80, // HTTPS endpoint is internet-exposed by definition.
		"auth_state":   55, // We can't determine auth requirement from probe alone.
		"capability":   50, // Default: hint only.
		"impact_class": 60, // Industrial process gateway.
		// cve_exposure for OPC UA stacks: handful of CVEs in the
		// Unified Automation + Prosys + open62541 stacks 2022-2025.
		"cve_exposure": 12,
	}
	if uaBinding {
		// Strong UA hit → bump capability + protocol_risk.
		factors["capability"] = 75
		factors["protocol_risk"] = 75
	}
	score := scoreFor(factors)
	_ = render.SafeBytes([]byte(statusLine))
	_ = serverHdr
	return &core.Finding{
		ID:          hashID(target, note),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, note),
	}
}

// scoreFor mirrors the existing opcua plugin's weighting so
// findings from both bindings score consistently.
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

func hashID(target core.Target, note string) core.UUID {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte(note))
	return core.UUID(hex.EncodeToString(h.Sum(nil)[:16]))
}

func hashBytes(target core.Target, note string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte(note))
	return h.Sum(nil)
}

// REPL stub — same pattern as opcua / fox; the generic framework
// will replace this in a future cycle.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return errors.New("opcuahttps: REPL arrives with the generic framework")
}

// ProxyHandler returns deny-all. OPC UA HTTPS writes carry the
// same SecureChannel + Session + Service request semantics as
// the binary binding; proxying them would let a client mutate
// PLC state through us. Mirrors the opcua plugin's deny stance.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

// denyAll satisfies core.ProxyHandler with a hang-up. For OPC UA
// HTTPS we drop the connection without emitting an HTTP 403 —
// SCADA clients reconnect anyway, and silence reduces our
// fingerprint at the proxy.
type denyAll struct{}

// Handle closes both ends; matches the opcua TCP plugin's deny
// pattern. No bytes ever flow.
func (h *denyAll) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return errors.New("opcuahttps: proxy denies client input by default")
}

// silence unused import; reserved for future header-detail
// expansion.
var _ = http.StatusOK
