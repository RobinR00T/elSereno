package s7

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
	"local/elsereno/internal/protocols/s7/wire"
)

// Name is the plugin identifier.
const Name = "s7"

// DefaultPort is the S7 well-known port (TPKT/COTP).
const DefaultPort core.Port = 102

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with conservative timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 5 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "S7comm (Siemens) TPKT/COTP read-only fingerprint on port 102",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe sends a COTP Connection Request wrapped in TPKT and
// classifies the response.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("s7: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if err := wire.WriteTPKT(conn, wire.BuildCOTPConnectionRequest()); err != nil {
		return nil, fmt.Errorf("s7: write CR: %w", err)
	}
	tpkt, err := wire.ReadTPKT(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return buildFinding(target, "silent close", false), nil
		}
		return nil, fmt.Errorf("s7: read: %w", err)
	}
	return buildFinding(target, classify(tpkt.Payload), wire.IsCOTPConfirm(tpkt.Payload)), nil
}

// REPL is planned for F4 chunk 2 (generic REPL framework).
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("s7: REPL arrives with the generic REPL framework")
}

// ProxyHandler returns a read-only pass-through. S7-level write
// commands will be filtered when the offensive build adds them (F5).
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

func classify(payload []byte) string {
	t, ok := wire.COTPType(payload)
	if !ok {
		return "empty COTP"
	}
	switch t {
	case wire.COTPConnectionConfirm:
		return "COTP Connection Confirm (S7 family likely)"
	case wire.COTPDisconnectRequest:
		return "COTP Disconnect Request"
	case wire.COTPData:
		return "COTP Data (unexpected for a bare CR probe)"
	default:
		return fmt.Sprintf("COTP type 0x%02x", t)
	}
}

func buildFinding(target core.Target, note string, isConfirm bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85,
		"exposure":      80,
		"auth_state":    85,
		"capability":    30,
		"impact_class":  80, // S7 PLCs drive safety-adjacent processes
		"cve_exposure":  0,
	}
	if isConfirm {
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
