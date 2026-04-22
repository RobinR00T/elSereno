package sip

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/sip/wire"
	"local/elsereno/internal/render"
)

// Name is the plugin identifier.
const Name = "sip"

// DefaultPort is the well-known UDP/TCP SIP port.
const DefaultPort core.Port = 5060

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	// Transport is "udp" (default) or "tcp". UDP is what
	// ~80% of SIP endpoints listen on by default; TCP is
	// used by phones behind CGNAT + by TLS deployments on
	// 5061 when `Plugin.TLSPort` is wired.
	Transport string
}

// Default returns a Plugin with sensible timeouts + UDP transport.
func Default() *Plugin {
	return &Plugin{
		DialTimeout: 3 * time.Second,
		IOTimeout:   2 * time.Second,
		Transport:   "udp",
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "SIP / PBX OPTIONS probe on 5060 — identifies Asterisk, FreePBX, 3CX, Cisco UCM, Mitel, Avaya, Yeastar, Grandstream, Fanvil, Yealink, Kamailio, OpenSIPS, FreeSWITCH, SER",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single OPTIONS request
// and classifies the reply by vendor.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	branch := randomBranch()
	req := wire.BuildOPTIONS(addr, branch)

	transport := p.Transport
	if transport == "" {
		transport = "udp"
	}

	resp, rawErr := p.sendAndRead(ctx, transport, addr, req)
	if rawErr != nil {
		// Connection refused / timed out / DNS — no finding at
		// all; the scanner treats that as a negative result.
		return nil, fmt.Errorf("sip: probe %s/%s: %w", transport, addr, rawErr)
	}

	note := "sip-responded"
	isSIP := wire.IsSIPStatus(resp.StatusLine)
	if !isSIP {
		note = "non-sip-bytes"
	}
	vendor := IdentifyVendor(resp.Server, resp.UserAgent)
	return buildFinding(target, resp, isSIP, vendor, note), nil
}

// sendAndRead does the actual packet send + response read. UDP
// and TCP paths are slightly different: UDP writes a datagram +
// does a single read; TCP opens a connection, writes the request,
// reads until a valid-looking CRLFCRLF delimits the headers.
func (p *Plugin) sendAndRead(ctx context.Context, transport, addr string, req []byte) (wire.Response, error) {
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, transport, addr)
	if err != nil {
		return wire.Response{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))
	if _, err := conn.Write(req); err != nil {
		return wire.Response{}, fmt.Errorf("write: %w", err)
	}
	if transport == "udp" {
		// UDP: read up to 4 KiB in one call; SIP status line +
		// headers almost always fit.
		buf := make([]byte, 4096)
		n, rerr := conn.Read(buf)
		if n == 0 && rerr != nil {
			return wire.Response{}, fmt.Errorf("read: %w", rerr)
		}
		return wire.ParseResponse(bytes.NewReader(buf[:n]))
	}
	// TCP: use wire.ParseResponse directly — it reads with
	// bufio + textproto which handles chunked header arrival.
	return wire.ParseResponse(conn)
}

// REPL stub (consistent with other plugins).
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("sip: REPL arrives with the generic framework")
}

// ProxyHandler returns the default deny-all proxy. SIP proxies
// are extremely sensitive: a single INVITE from a client routed
// to the wrong upstream can trigger a real PSTN call + billing.
// The default build refuses every client byte. The offensive
// build (v1.4) ships a write-gated variant with per-method
// allowlist.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

// Handle emits a SIP 403 Forbidden on the client stream and
// returns. Real SIP clients parse this correctly.
func (denyAll) Handle(_ context.Context, client, _ io.ReadWriter) error {
	_, _ = client.Write([]byte(
		"SIP/2.0 403 Forbidden\r\n" +
			"Server: ElSereno proxy (read-only)\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	))
	return fmt.Errorf("sip: proxy refuses client input by default (offensive v1.4 adds the gated proxy)")
}

// buildFinding renders a scored finding from the response +
// vendor classification.
func buildFinding(target core.Target, resp wire.Response, isSIP bool, vendor Vendor, note string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 70, // default for "SIP-looking but unknown vendor"
		"exposure":      80, // SIP on the public internet is nearly always a finding
		"auth_state":    60, // OPTIONS often bypasses auth; 401 on REGISTER is the real gate
		"capability":    30,
		"impact_class":  75, // toll fraud + call hijack
		"cve_exposure":  0,
	}
	if isSIP {
		factors["capability"] = 60
		factors["protocol_risk"] = VendorRisk(vendor)
	}
	// A vendor with a specific 401 challenge is slightly worse
	// than a server that just 200-OK's an OPTIONS.
	if isSIP && resp.Code == 401 {
		factors["auth_state"] = 50
	}
	score := scoreFor(factors)
	_ = render.SafeBytes // keep the import live for future payload embedding

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

// randomBranch returns a hex-encoded 8-byte random suffix used
// as the SIP Via branch cookie (RFC 3261 §8.1.1.7 requires a
// "z9hG4bK" prefix + "unique" suffix — a cryptographic random
// satisfies that).
func randomBranch() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
