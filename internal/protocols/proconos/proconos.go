package proconos

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
	"local/elsereno/internal/protocols/proconos/wire"
)

// Name is the plugin identifier.
const Name = "proconos"

// DefaultPort is the canonical ProConOS runtime port.
const DefaultPort core.Port = 20547

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
		Description: "KW-Software ProConOS runtime fingerprint on TCP/20547 (best-effort; ILC + Berghof + IPC2u + ABB/B&R/Lenze re-skins) — needs real-PLC validation",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends the canonical 16-byte
// ProConOS hello and classifies the response by either:
//   - first 4 bytes echoing the ProConOS hello prefix, or
//   - any of the ProConOS banner markers (PROCONOS / ProConOS /
//     KW-Software / MultiProg / KWS-LDR / alt-prefix).
//
// No service-request frames are issued — the default build is
// read-only by design.
//
// HONEST SCOPE NOTE: positives ship at ~0.7 confidence rather
// than the ~0.95 the v1.20-v1.25 plugins produce. See package
// docstring.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proconos: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildHello()); err != nil {
		return nil, fmt.Errorf("proconos: write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return buildFinding(target, "no usable reply", false), nil
	}
	note, cerr := wire.Classify(buf[:n])
	if cerr != nil {
		return buildFinding(target, classifyParseError(cerr), false), nil
	}
	return buildFinding(target, "ProConOS "+note, true), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("proconos: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("proconos: TCP proxy framework requires a ProConOS-aware classifier; v1.28 is fingerprint-only — best-effort wire interpretation needs real-PLC validation before per-frame gating ships")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short ProConOS reply"
	case errors.Is(err, wire.ErrNotProConOS):
		return "ProConOS hello got non-ProConOS reply"
	default:
		return "ProConOS classify failure"
	}
}

func buildFinding(target core.Target, note string, isProConOS bool) *core.Finding {
	factors := map[string]int{
		// Lower than codesys/pcworx (80) because the plugin's
		// wire interpretation is best-effort + needs PLC
		// validation. Operators should treat positives at
		// confidence ~0.7.
		"protocol_risk": 75,
		"exposure":      75,
		"auth_state":    90, // ProConOS default install has no enforced auth
		"capability":    30,
		"impact_class":  75, // factory-floor PLC blast radius
		// cve_exposure: 7 — KW-Software runtime ecosystem
		// inherits much of the Phoenix Contact ILC family's
		// CVE record. Anchor advisories:
		//   ICSA-15-160-01 (PCWorx auth bypass + RCE — also
		//                   affects ProConOS-only Berghof +
		//                   Lenze deployments).
		//   ICSA-17-201-01 (PCWorx + ProConOS variable-write
		//                   privilege escalation).
		//   ICSA-18-296-01 (KW Multiprog development environment
		//                   RCE).
		"cve_exposure": 7,
	}
	if isProConOS {
		// Capped at 60 (lower than the 70-75 of codesys / pcworx)
		// to reflect the best-effort confidence.
		factors["capability"] = 60
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
