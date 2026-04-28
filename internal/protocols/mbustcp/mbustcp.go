package mbustcp

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
	"local/elsereno/internal/protocols/mbustcp/wire"
)

// Name is the plugin identifier.
const Name = "mbustcp"

// DefaultPort is the most common Internet-exposed M-Bus TCP port
// (TCP/10001 is the canonical default for Relay GmbH and Solvimus
// gateways; TCP/8888 and TCP/2055 also seen in the wild).
const DefaultPort core.Port = 10001

// Plugin implements core.Protocol over TCP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 5 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "M-Bus over TCP read-only fingerprint on TCP/10001 (smart-meter gateways: water/gas/heat/electricity)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single REQ_UD2 short
// frame to the broadcast primary address (0xFE) and folds the
// parsed manufacturer ID + medium byte from the RSP_UD long
// frame into the finding hash. No SND_UD (write user data) is
// performed.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mbustcp: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildREQUD2(0xFE)); err != nil {
		return nil, fmt.Errorf("mbustcp: write: %w", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return buildFinding(target, "no usable reply", false), nil
	}
	if wire.IsACK(buf[:n]) {
		return buildFinding(target, "M-Bus ACK only", true), nil
	}
	if !wire.IsRSPUD(buf[:n]) {
		return buildFinding(target, fmt.Sprintf("non-M-Bus response (%d bytes)", n), false), nil
	}
	mi, perr := wire.ParseRSPUD(buf[:n])
	if perr != nil {
		return buildFinding(target, classifyParseError(perr), false), nil
	}
	note := fmt.Sprintf("M-Bus manuf=%s medium=0x%02x ver=0x%02x", mi.Manufacturer, mi.Medium, mi.Version)
	return buildFinding(target, note, true), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("mbustcp: REPL arrives with the generic framework")
}

// ProxyHandler returns a wire-layer write-ban handler. M-Bus is
// TCP-wrapped; the proxy reads the first frame from the client
// and replies with a single-byte ACK (0xE5) without forwarding to
// upstream. This matches the M-Bus protocol's link-layer ACK
// idiom — the meter reports nothing went wrong but no data is
// returned, which is the closest thing to a "request denied"
// response in the protocol.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &writeBanHandler{} }

type writeBanHandler struct{}

func (writeBanHandler) Handle(ctx context.Context, client, _ io.ReadWriter) error {
	// Read up to 256 bytes (long M-Bus frame max ~260) from the
	// client.
	buf := make([]byte, 260)
	n, err := client.Read(buf)
	if err != nil {
		return err
	}
	_ = n
	// Reply with single-byte ACK.
	if _, err := client.Write([]byte{0xE5}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short M-Bus frame"
	case errors.Is(err, wire.ErrBadStart):
		return "M-Bus start byte not 0x68"
	case errors.Is(err, wire.ErrLengthMismatch):
		return "M-Bus length-field disagreement"
	case errors.Is(err, wire.ErrBadStop):
		return "M-Bus stop byte not 0x16"
	case errors.Is(err, wire.ErrChecksumMismatch):
		return "M-Bus checksum mismatch"
	case errors.Is(err, wire.ErrNotVarDataResponse):
		return "M-Bus CI not 0x72 (not variable-data response)"
	default:
		return "M-Bus parse failure"
	}
}

func buildFinding(target core.Target, note string, isMBus bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 70, // smart meters; less direct kinetic impact than PLCs
		"exposure":      70,
		"auth_state":    90, // M-Bus has no native authentication on the wire
		"capability":    30,
		"impact_class":  60, // billing accuracy + privacy of consumption data
		"cve_exposure":  0,
	}
	if isMBus {
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
