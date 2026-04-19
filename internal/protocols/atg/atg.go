package atg

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
	"local/elsereno/internal/render"
)

// Name is the plugin identifier.
const Name = "atg"

// DefaultPort is the well-known port.
const DefaultPort core.Port = 10001

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
		Description: "ATG Veeder-Root TLS-350/4 I20100 fingerprint on port 10001",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// IsATGResponse checks whether a banner matches the Veeder-Root
// I20100 reply shape ("I20100" header followed by tank data, 0x03
// end-of-message sentinel).
func IsATGResponse(banner string) bool {
	b := strings.ToUpper(banner)
	return strings.Contains(b, "I20100") || strings.Contains(b, "IN-TANK") || strings.Contains(b, "VEEDER")
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("atg: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))
	// \x01I20100\n — the classic Veeder-Root "system status" query.
	if _, err := conn.Write([]byte{0x01, 'I', '2', '0', '1', '0', '0', '\r', '\n'}); err != nil {
		return nil, fmt.Errorf("atg: write: %w", err)
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	safe := render.SafeBytes(buf[:n])
	isATG := IsATGResponse(safe)
	note := "no ATG response"
	if isATG {
		note = "ATG I20100 response"
	}
	return buildFinding(target, note, isATG), nil
}

// REPL stub until the generic REPL framework lands.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("atg: REPL arrives with the generic framework")
}

// ProxyHandler returns a read-only pass-through (write-gating in F5).
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &passThrough{} }

type passThrough struct{}

func (passThrough) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	errs := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, client); errs <- err }()
	go func() { _, err := io.Copy(client, upstream); errs <- err }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

func buildFinding(target core.Target, note string, isATG bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 75,
		"exposure":      80,
		"auth_state":    95, // ATG has no auth
		"capability":    30,
		"impact_class":  60, // fuel dispensing impact
		"cve_exposure":  0,
	}
	if isATG {
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
