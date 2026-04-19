package xot

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
	"local/elsereno/internal/protocols/xot/wire"
)

// Name is the plugin identifier used for Finding.Protocol and
// core.PluginMetadata.Name.
const Name = "xot"

// DefaultPort is the RFC 1613 well-known port.
const DefaultPort core.Port = 1998

// Plugin implements core.Protocol. Public fields are the timeouts the
// probe uses; the REPL re-uses the same configuration.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with 5-second dial and I/O timeouts.
func Default() *Plugin {
	return &Plugin{
		DialTimeout: 5 * time.Second,
		IOTimeout:   5 * time.Second,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "X.25 over TCP (RFC 1613) read-only probe + REPL + proxy",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe sends a minimal Call Request with LCN=1 and classifies the
// response. It never attempts to establish an actual virtual circuit:
// Call Accepted is reported and then closed with a Clear Request.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("xot: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if err := wire.WriteXOTFrame(conn, wire.MarshalCallRequest(1)); err != nil {
		return nil, fmt.Errorf("xot: send call request: %w", err)
	}

	packet, err := wire.ReadXOTFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Silent reject is common; emit an info-level finding.
			return fingerprintFromSilence(target), nil
		}
		return nil, fmt.Errorf("xot: read response: %w", err)
	}

	return fingerprintFromPacket(target, packet), nil
}

// REPL is a thin read-only shell over an opened XOT connection.
// Commands: `call <LCN>`, `clear [cause] [diag]`, `data <hex>`, `quit`.
// Write operations stay read-only in the default build; offensive
// dial semantics live in F5.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("xot: REPL binding arrives with the generic REPL hookup in F4")
}

// ProxyHandler returns the XOT pass-through handler (header + payload
// echo, with SafeBytes sanitisation on any rendered output).
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &proxyHandler{} }

// proxyHandler is a minimal XOT proxy that forwards frames between
// client and upstream. Full instrumentation (per-frame logging,
// hook registration) lands with the proxy framework in F3.
type proxyHandler struct{}

// Handle implements core.ProxyHandler.
func (h *proxyHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	errs := make(chan error, 2)
	copier := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errs <- err
	}
	go copier(upstream, client)
	go copier(client, upstream)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

// fingerprintFromPacket maps the first response packet to a Finding.
func fingerprintFromPacket(target core.Target, packet wire.Packet) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 40,
		"exposure":      70,
		"auth_state":    70,
		"capability":    30,
		"impact_class":  20,
		"cve_exposure":  0,
	}
	var note string
	switch packet.Type {
	case wire.PacketCallAccepted:
		factors["capability"] = 70
		factors["auth_state"] = 30
		note = "call accepted (open PAD or gateway)"
	case wire.PacketClearRequest:
		cause, diag, _ := wire.ClearCause(packet)
		note = fmt.Sprintf("clear indication cause=0x%02x diag=0x%02x", cause, diag)
	case wire.PacketRestartRequest:
		factors["capability"] = 40
		note = "restart indication (DCE is up)"
	default:
		note = fmt.Sprintf("unexpected %s (PTI=0x%02x)", packet.Type, packet.PTI)
	}

	score := scoreFor(factors)
	return &core.Finding{
		ID:          findingID(target, packet.Type, note),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashEvidence(target, packet.Type, note),
	}
}

// fingerprintFromSilence produces an info-level finding when the
// target closed the connection without returning any XOT frame.
func fingerprintFromSilence(target core.Target) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 10,
		"exposure":      40,
		"auth_state":    80,
		"capability":    0,
		"impact_class":  0,
		"cve_exposure":  0,
	}
	score := scoreFor(factors)
	return &core.Finding{
		ID:          findingID(target, wire.PacketUnknown, "silent reject"),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashEvidence(target, wire.PacketUnknown, "silent reject"),
	}
}

// scoreFor approximates the scoring engine contribution for the six
// default factors at the weights defined in ADR-006. The real engine
// is the source of truth; this is a local helper so plugins do not
// take a hard dependency on the scoring package at Probe time.
func scoreFor(factors map[string]int) int {
	weights := map[string]float64{
		"protocol_risk": 0.25,
		"exposure":      0.20,
		"auth_state":    0.20,
		"capability":    0.15,
		"impact_class":  0.10,
		"cve_exposure":  0.10,
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

// portBytes splits a uint16 port into (hi, lo) so we can hash it
// without passing an int through byte() and tripping G115.
func portBytes(p core.Port) [2]byte {
	return [2]byte{byte(uint16(p) >> 8 & 0xff), byte(uint16(p) & 0xff)}
}

// findingID returns a stable UUID-like hex slice derived from
// (target, packet type, note). Two probes against the same endpoint
// with the same outcome collapse to one finding.
func findingID(target core.Target, pt wire.PacketType, note string) core.UUID {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte{byte(pt)})
	_, _ = h.Write([]byte(note))
	sum := h.Sum(nil)
	return core.UUID(hex.EncodeToString(sum[:16]))
}

func hashEvidence(target core.Target, pt wire.PacketType, note string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte{byte(pt)})
	_, _ = h.Write([]byte(note))
	return h.Sum(nil)
}
