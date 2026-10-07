package fox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/netutil"
	"local/elsereno/internal/render"
	"local/elsereno/internal/scoring"
)

// Name is the plugin identifier.
const Name = "fox"

// DefaultPort is the well-known port.
const DefaultPort core.Port = 1911

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "Niagara Fox (Tridium) fingerprint on 1911: sends the client hello, classifies the station's reply",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// HelloRequest is the client hello a Niagara station waits for before
// it says anything: byte for byte the query of nmap's fox-info.nse, and
// the opening of the Workbench hello in w3h/icsmaster fox_info.pcap
// (where the client speaks first and the station answers).
const HelloRequest = "fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"

// IsFoxBanner reports whether reply is a Niagara station's Fox message:
// it starts with "fox a 0" (a station's messages do; a client's, like
// HelloRequest, start "fox a 1") and carries a "{" dictionary, the check
// nmap's fox-info.nse makes. Until 2026-10-07 any text containing
// "fox a " or "fox.version" anywhere counted, which our own hello, once
// the probe sends one, also satisfies (PITF-078).
func IsFoxBanner(reply string) bool {
	return strings.HasPrefix(reply, "fox a 0") && strings.Contains(reply, "{")
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fox: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	// A station says nothing until the client says hello; until
	// 2026-10-07 the probe only listened, so a real station never
	// answered (PITF-078).
	hello := []byte(HelloRequest)
	if _, err := conn.Write(hello); err != nil {
		return nil, fmt.Errorf("fox: write hello: %w", err)
	}
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	if netutil.IsEcho(hello, buf[:n]) {
		return buildFinding(target, "reply echoes the probe (not Fox)", false), nil
	}
	safe := render.SafeBytes(buf[:n])
	isFox := IsFoxBanner(safe)
	note := "no fox banner"
	if isFox {
		note = "fox banner detected"
	}
	return buildFinding(target, note, isFox), nil
}

// REPL stub until the generic REPL framework lands.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("fox: REPL arrives with the generic framework")
}

// ProxyHandler returns the default Fox proxy, which refuses every
// client→upstream byte with a "fox a 0 -1 fox denied\n" line and
// closes the connection (ADR-040). Niagara Fox is a line-oriented
// administrative protocol, any client input can mutate state, so
// the default build offers no legitimate proxy use. The offensive
// build substitutes a handler that allows `fox a 0 -1 fox hello`
// handshake and routes everything else through triple confirm.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

func (denyAll) Handle(_ context.Context, client, _ io.ReadWriter) error {
	_, _ = client.Write([]byte("fox a 0 -1 fox denied\n"))
	return fmt.Errorf("fox: proxy refuses client input by default (use -tags offensive + triple confirm)")
}

func buildFinding(target core.Target, note string, isFox bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // BMS control plane
		"exposure":      80,
		"auth_state":    75,
		"capability":    30,
		"impact_class":  80,
		// cve_exposure 13: Tridium Niagara dominates large-scale BMS, so
		// even modest CVE counts hit a wide install base. Web-verified
		// examples: CVE-2012-3024 (Niagara AX predictable session
		// IDs/keys, auth bypass by brute force) and CVE-2017-16744
		// (Niagara AX / N4 path traversal). The previous comment also
		// listed CVE-2015-2916, which is real but belongs to Securifi
		// Almond (a CSRF), not Niagara; dropped, see PITF-070.
		"cve_exposure": 13,
	}
	if isFox {
		factors["capability"] = 70
	}
	score := scoring.ScoreDefault(factors)
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
