package bacnet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/bacnet/wire"
)

// Name is the plugin identifier.
const Name = "bacnet"

// DefaultPort is the BACnet/IP well-known UDP port.
const DefaultPort core.Port = 47808

// Plugin implements core.Protocol (UDP probe).
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 3 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "BACnet/IP Who-Is read-only fingerprint on UDP/47808",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("bacnet: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))
	if _, err := conn.Write(wire.BuildWhoIs()); err != nil {
		return nil, fmt.Errorf("bacnet: write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return buildFinding(target, "no reply", false), nil
	}
	if n < 6 {
		return buildFinding(target, fmt.Sprintf("short reply (%d)", n), false), nil
	}
	// BVLC(4) NPDU(2) APDU(rest).
	if _, perr := wire.ParseBVLC(buf[:n]); perr != nil {
		return buildFinding(target, "not bacnet", false), nil
	}
	if wire.IsIAm(buf[6:n]) {
		return buildFinding(target, "I-Am", true), nil
	}
	return buildFinding(target, fmt.Sprintf("BVLC ok, apdu[0]=0x%02x", buf[6]), false), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("bacnet: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. BACnet/IP is UDP; the
// generic TCP proxy framework in internal/proxy cannot legitimately
// relay BACnet traffic. Rather than silently shuttle bytes that are
// not BACnet frames, the handler refuses the session immediately.
// A dedicated UDP relay arrives with the BACnet write plugin in the
// offensive build (ADR-040).
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("bacnet: TCP proxy framework does not support UDP BACnet/IP; use -tags offensive for the dedicated UDP relay")
}

func buildFinding(target core.Target, note string, isIAm bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 75,
		"exposure":      75,
		"auth_state":    85,
		"capability":    30,
		"impact_class":  70, // BACnet drives HVAC; BMS / life safety adjacent
		"cve_exposure":  0,
	}
	if isIAm {
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
