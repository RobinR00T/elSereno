package pcworx

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
	"local/elsereno/internal/protocols/pcworx/wire"
)

// Name is the plugin identifier.
const Name = "pcworx"

// DefaultPort is the canonical PCWorx TCP port. Older firmwares
// also bind 41100 (configuration server) and 41101 (web admin),
// but 1962 is the runtime-protocol default that every ILC
// release accepts.
const DefaultPort core.Port = 1962

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
		Description: "Phoenix Contact PCWorx read-only fingerprint on TCP/1962 (ILC 130/150/170/191/350/370/390 + AXC F + RFC 460R/470S PLCs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends the canonical 32-byte
// PCWorx hello and classifies the response by either:
//   - first 4 bytes echoing the PCWorx hello prefix, or
//   - any of the PCWorx banner markers (ILC / AXC F / RFC /
//     Phoenix / PCWorx / ProConOS / "FW V" / "Boot V").
//
// No service-request frames are issued — the default build is
// read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("pcworx: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildHello()); err != nil {
		return nil, fmt.Errorf("pcworx: write: %w", err)
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
	return buildFinding(target, "PCWorx "+note, true), nil
}

// REPL stub — consistent with every other protocol plugin.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("pcworx: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. PCWorx is a
// proprietary binary protocol whose deeper layers (variable
// read / write / runtime control) are not implemented in v1.25;
// the default-build proxy refuses the session immediately
// rather than relay bytes that may or may not be PCWorx frames.
// A dedicated relay arrives with the future offensive plugin.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("pcworx: TCP proxy framework requires a PCWorx-aware classifier; v1.25 is fingerprint-only — a relay arrives with the future offensive plugin")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short PCWorx reply"
	case errors.Is(err, wire.ErrNotPCWorx):
		return "PCWorx hello got non-PCWorx reply"
	default:
		return "PCWorx classify failure"
	}
}

func buildFinding(target core.Target, note string, isPCWorx bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // ILC PLCs control real machinery
		"exposure":      75,
		"auth_state":    90, // PCWorx default install has no enforced auth
		"capability":    30,
		"impact_class":  75, // factory-floor PLC blast radius
		// cve_exposure: 8 — Phoenix Contact ILC family has a
		// recurring CVE history. Anchor advisories:
		//   ICSA-15-160-01 (PCWorx auth bypass + RCE).
		//   ICSA-17-201-01 (PCWorx variable-write privilege escalation).
		//   ICSA-21-082-01 (AXC F 2152 hardcoded credentials).
		//   CVE-2018-13002 (ILC 1xx config-file read without auth).
		//   CVE-2020-9436  (ILC 350/370/390 stack DoS).
		"cve_exposure": 8,
	}
	if isPCWorx {
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
