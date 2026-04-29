package codesys

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
	"local/elsereno/internal/protocols/codesys/wire"
)

// Name is the plugin identifier.
const Name = "codesys"

// DefaultPort is the CoDeSys V3 Gateway-Server TCP port. Some
// installations also bind 11740 (newer) or 1200 (V2 legacy);
// we probe the canonical V3 default 1217.
const DefaultPort core.Port = 1217

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
		Description: "CoDeSys V3 read-only fingerprint on TCP/1217 (Wago / Beckhoff alt / Schneider M251 / Eaton / Bosch Rexroth soft-PLCs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends the 4-byte BlockDriver
// magic hello and classifies the response by either:
//   - first 4 bytes echoing the BlockDriver magic, or
//   - any of the canonical CoDeSys banner substrings
//     (CoDeSys / CODESYS / 3S-Smart / 3S-CoDeSys / CmpHostname /
//     CmpAppBP / CmpRuntime).
//
// No service-request APDUs are issued — the default build is
// read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("codesys: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildHello()); err != nil {
		return nil, fmt.Errorf("codesys: write: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return buildFinding(target, "no usable reply", false), nil
	}
	note, cerr := wire.Classify(buf[:n])
	if cerr != nil {
		return buildFinding(target, classifyParseError(cerr), false), nil
	}
	return buildFinding(target, "CoDeSys "+note, true), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("codesys: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. CoDeSys V3 is a
// proprietary tag-length-value protocol whose deeper layers
// (Layer-3 / Layer-4 / Layer-7 of the 3S stack) are not
// implemented in v1.22 chunk 2; the default-build proxy refuses
// the session immediately rather than relay bytes that may or
// may not be CoDeSys frames. A dedicated relay arrives with the
// future offensive plugin.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("codesys: TCP proxy framework requires a CoDeSys-aware classifier; v1.22 chunk 2 is fingerprint-only — a relay arrives with the future offensive plugin")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short CoDeSys reply"
	case errors.Is(err, wire.ErrNotCoDeSys):
		return "CoDeSys hello got non-CoDeSys reply"
	default:
		return "CoDeSys classify failure"
	}
}

func buildFinding(target core.Target, note string, isCoDeSys bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // soft-PLC runtime, kinetic effects
		"exposure":      75,
		"auth_state":    85, // CoDeSys V3 supports password / OAUTH but many deployments don't enforce
		"capability":    30,
		"impact_class":  75, // factory-floor PLC blast radius
		"cve_exposure":  10, // ICSA-12-242-01 / 19-080-01 / 21-014-04 — well-known CVEs
	}
	if isCoDeSys {
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
