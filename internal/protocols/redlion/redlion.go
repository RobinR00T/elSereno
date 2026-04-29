package redlion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/redlion/wire"
)

// Name is the plugin identifier.
const Name = "redlion"

// DefaultPort is the canonical Red Lion Net (RLN) TCP port. G3
// / Graphite / FlexEdge / DA-50N HMIs and the Sixnet RTU
// variants bind here. Some installations also expose 23
// (telnet) and 80 (HTTP) for the same device.
const DefaultPort core.Port = 789

// Plugin implements core.Protocol over TCP.
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
		Description: "Red Lion Crimson / RLN read-only fingerprint on TCP/789 (G3 / Graphite / FlexEdge / DA-50N / Sixnet HMIs and RTUs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Connects to TCP/789, sends a
// 3-byte zero-padded hello to elicit the banner, and classifies
// the response by canonical Red Lion substring (Red Lion / Red
// Lion Controls / Crimson 3 / FlexEdge / Graphite / DA-50N /
// G3 / Sixnet). Many RLN servers send their banner unsolicited
// on connect; the hello is a fallback for gateways that
// require a probe byte.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("redlion: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	// First: try to read an unsolicited banner.
	buf := make([]byte, 1024)
	_ = conn.SetReadDeadline(time.Now().Add(p.IOTimeout / 2))
	n, _ := conn.Read(buf)
	if n > 0 {
		if note, cerr := wire.Classify(buf[:n]); cerr == nil {
			return buildFinding(target, "Red Lion "+note, true), nil
		}
	}
	// Fallback: send the 3-byte hello and try again.
	_ = conn.SetWriteDeadline(time.Now().Add(p.IOTimeout))
	if _, err := conn.Write(wire.BuildHello()); err != nil {
		if n == 0 {
			return buildFinding(target, "no usable reply", false), nil
		}
		return buildFinding(target, "non-Red-Lion reply", false), nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(p.IOTimeout))
	n2, _ := conn.Read(buf[n:])
	total := n + n2
	if total < 4 {
		return buildFinding(target, "no usable reply", false), nil
	}
	note, cerr := wire.Classify(buf[:total])
	if cerr != nil {
		return buildFinding(target, classifyParseError(cerr), false), nil
	}
	return buildFinding(target, "Red Lion "+note, true), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("redlion: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. RLN is a
// proprietary tag-length-value protocol whose deeper layers are
// not implemented in v1.22 chunk 3; the default-build proxy
// refuses sessions immediately.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("redlion: TCP proxy framework requires an RLN-aware classifier; v1.22 chunk 3 is fingerprint-only — a relay arrives with the future offensive plugin")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short Red Lion reply"
	case errors.Is(err, wire.ErrNotRedLion):
		return "non-Red-Lion reply"
	default:
		return "Red Lion classify failure"
	}
}

func buildFinding(target core.Target, note string, isRedLion bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 75, // HMI / RTU runtime
		"exposure":      75,
		"auth_state":    85, // Crimson 3 supports passwords but many deployments don't enforce
		"capability":    30,
		"impact_class":  70, // HMI manipulation + RTU SCADA bridge effects
		"cve_exposure":  5,  // smaller than CoDeSys but ICSA-21-103-01 + ICSA-22-088-01 are known
	}
	if isRedLion {
		factors["capability"] = 70
	}
	score := scoreFor(factors)
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
