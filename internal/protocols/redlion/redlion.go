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
	"local/elsereno/internal/netutil"
	"local/elsereno/internal/protocols/redlion/wire"
	"local/elsereno/internal/scoring"
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
		Description: "Red Lion Crimson v3 (CR3) read-only fingerprint on TCP/789: reads the manufacturer and model registers (G3 / Graphite / FlexEdge / DA-50N HMIs, Sixnet RTUs)",
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

	// A panel says nothing until asked: read the manufacturer register
	// as cr3-fingerprint.nse does. Until 2026-10-07 the probe waited for
	// a connect banner and then sent three zero bytes, neither of which
	// any source supports (PITF-079).
	query := append([]byte(nil), wire.ManufacturerQuery...)
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("redlion: write: %w", err)
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if netutil.IsEcho(query, buf[:n]) {
		return buildFinding(target, "reply echoes the probe (not Red Lion)", false), nil
	}
	note, cerr := wire.Classify(buf[:n])
	if cerr != nil {
		if n == 0 {
			return buildFinding(target, "no usable reply", false), nil
		}
		return buildFinding(target, classifyParseError(cerr), false), nil
	}
	if model := readModel(conn, p.IOTimeout); model != "" {
		note += " model=" + model
	}
	return buildFinding(target, "Red Lion "+note, true), nil
}

// readModel reads the model register on the same connection, best
// effort: an empty string when the panel does not answer it.
func readModel(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(wire.ModelQuery); err != nil {
		return ""
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	model, ok := wire.IsStringResponseTo(buf[:n], wire.ModelQuery)
	if !ok {
		return ""
	}
	return model
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
	return fmt.Errorf("redlion: TCP proxy framework requires an RLN-aware classifier; v1.22 chunk 3 is fingerprint-only, a relay arrives with the future offensive plugin")
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
