package profinetcm

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/profinetcm/wire"
	"local/elsereno/internal/scoring"
)

// Name is the plugin identifier.
const Name = "profinet-cm"

// Plugin implements core.Protocol over UDP.
type Plugin struct {
	IOTimeout time.Duration
}

// Default returns a Plugin with a sensible timeout.
func Default() *Plugin { return &Plugin{IOTimeout: 3 * time.Second} }

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "PROFINET IO opt-in identification on UDP/34964: one DCE/RPC EPM lookup, reads device type and order number (spec-grounded, not capture-validated; run with --plugin profinet-cm --target host:34964)",
		DefaultPort: 0,
		Build:       "default",
		Version:     "v1",
		OptIn:       true,
	}
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	r, err := p.Lookup(ctx, target)
	switch {
	case err != nil:
		return buildFinding(target, err.Error(), 30), nil
	case r.PType != wire.PTypeResponse:
		return buildFinding(target, fmt.Sprintf("DCE/RPC endpoint answered (ptype %d), PNIO interface not confirmed", r.PType), 55), nil
	}
	return buildFinding(target, "PROFINET IO device: "+r.Annotation, 80), nil
}

// Lookup sends the EPM lookup and returns the classified reply.
func (p *Plugin) Lookup(ctx context.Context, target core.Target) (wire.Reply, error) {
	var activity [16]byte
	if _, err := cryptorand.Read(activity[:]); err != nil {
		return wire.Reply{}, fmt.Errorf("profinet-cm: activity id: %w", err)
	}
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", ":0")
	if err != nil {
		return wire.Reply{}, fmt.Errorf("profinet-cm: listen: %w", err)
	}
	defer func() { _ = pc.Close() }()
	deadline := time.Now().Add(p.IOTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = pc.SetDeadline(deadline)
	dst := &net.UDPAddr{IP: target.Address.AsSlice(), Port: int(target.Port)}
	if _, err := pc.WriteTo(wire.BuildLookup(activity), dst); err != nil {
		return wire.Reply{}, fmt.Errorf("profinet-cm: write: %w", err)
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return wire.Reply{}, errors.New("no reply to EPM lookup")
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || !ua.IP.Equal(dst.IP) {
			continue // another host: not ours
		}
		r, cerr := wire.Classify(buf[:n], activity)
		if errors.Is(cerr, wire.ErrActivity) {
			continue
		}
		if cerr != nil {
			return wire.Reply{}, fmt.Errorf("non-PNIO reply: %w", cerr)
		}
		return r, nil
	}
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("profinet-cm: probe-only plugin has no REPL")
}

// ProxyHandler fails closed: PNIO-CM is UDP with ephemeral reply ports.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("profinet-cm: no proxy (UDP DCE/RPC with ephemeral reply ports)")
}

func buildFinding(target core.Target, note string, capability int) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 75, // PROFINET IO: controller-to-device I/O, no authentication in CM
		"exposure":      75,
		"auth_state":    85,
		"capability":    capability,
		"impact_class":  75,
		"cve_exposure":  10, // qualitative: CVEs are keyed to the order number, matched elsewhere (PITF-070)
	}
	score := scoring.ScoreDefault(factors)
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte(note))
	sum := h.Sum(nil)
	return &core.Finding{
		ID:          core.UUID(hex.EncodeToString(sum[:16])),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: sum,
	}
}

func portBytes(p core.Port) [2]byte {
	return [2]byte{byte(uint16(p) >> 8 & 0xff), byte(uint16(p) & 0xff)}
}
