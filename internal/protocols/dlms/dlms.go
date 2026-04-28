package dlms

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
	"local/elsereno/internal/protocols/dlms/wire"
)

// Name is the plugin identifier.
const Name = "dlms"

// DefaultPort is the DLMS/COSEM TCP well-known port (IEC 62056-46
// wrapper). Smart electricity meters and gas-grid concentrators
// typically bind here.
const DefaultPort core.Port = 4059

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
		Description: "DLMS/COSEM read-only fingerprint on TCP/4059 (IEC 62056-46 smart electricity / gas meters)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single AARQ
// (Application Association Request) wrapped in the DLMS TCP
// wrapper and classifies the response by wrapper version + AARE
// tag presence. No GET-Request / SET-Request / ACTION-Request
// services are issued.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dlms: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildAARQ()); err != nil {
		return nil, fmt.Errorf("dlms: write: %w", err)
	}

	buf := make([]byte, 256)
	n, err := io.ReadFull(conn, buf[:wire.WrapperLen])
	if err != nil {
		return buildFinding(target, "no usable reply", false), nil
	}
	if !wire.IsWrapperResponse(buf[:n]) {
		return buildFinding(target, fmt.Sprintf("non-DLMS response (%d bytes)", n), false), nil
	}
	apduLen := int(buf[6])<<8 | int(buf[7])
	if apduLen > 8192 {
		return buildFinding(target, fmt.Sprintf("absurd DLMS APDU length (%d)", apduLen), false), nil
	}
	total := wire.WrapperLen + apduLen
	if total > len(buf) {
		bigger := make([]byte, total)
		copy(bigger, buf[:n])
		buf = bigger
	}
	if _, err := io.ReadFull(conn, buf[n:total]); err != nil {
		return buildFinding(target, fmt.Sprintf("short DLMS APDU (declared %d)", apduLen), false), nil
	}
	info, cerr := wire.ClassifyResponse(buf[:total])
	if cerr != nil {
		// Wrapper-shape only — that's still a positive ID.
		return buildFinding(target, classifyParseError(cerr), true), nil
	}
	note := fmt.Sprintf("DLMS AARE src=0x%04x dst=0x%04x apdu=%d", info.SourceWPort, info.DestWPort, info.APDULen)
	return buildFinding(target, note, true), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("dlms: REPL arrives with the generic framework")
}

// ProxyHandler returns a wire-layer write-ban handler. Reads the
// 8-byte wrapper header from the client, drains the declared
// APDU body, and replies with a wrapper-framed AARE that carries
// a result-source-diagnostic = "no-reason-given" (associated-
// result rejected). Does NOT forward to upstream.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &writeBanHandler{} }

type writeBanHandler struct{}

func (writeBanHandler) Handle(ctx context.Context, client, _ io.ReadWriter) error {
	hdr := make([]byte, wire.WrapperLen)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return err
	}
	apduLen := int(hdr[6])<<8 | int(hdr[7])
	if apduLen > 8192 {
		return fmt.Errorf("dlms: oversized APDU (declared %d)", apduLen)
	}
	body := make([]byte, apduLen)
	if _, err := io.ReadFull(client, body); err != nil {
		return err
	}
	// Reply with a 16-byte AARE: 8-byte wrapper + 8-byte minimal
	// AARE-PDU (associate-result rejected, BER end-of-content
	// pad to round to 8 bytes).
	resp := []byte{
		0x00, 0x01, // wrapper version
		0x00, 0x01, // src wPort (server mgmt)
		0x00, 0x10, // dst wPort (client mgmt)
		0x00, 0x08, // apdu len 8
		0x61, 0x06, // AARE-PDU, len 6
		0xA2, 0x03, // associate-result [2]
		0x02, 0x01, 0x01, // INTEGER 1 (rejected-permanent)
		0x00, // BER end-of-content (pads to 8-byte APDU)
	}
	if _, err := client.Write(resp); err != nil {
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
		return "short DLMS frame"
	case errors.Is(err, wire.ErrBadWrapperVersion):
		return "DLMS wrapper version not 0x0001"
	case errors.Is(err, wire.ErrLengthMismatch):
		return "DLMS wrapper length disagreement"
	case errors.Is(err, wire.ErrNotAARE):
		return "DLMS APDU not AARE (tag != 0x61)"
	default:
		return "DLMS classify failure"
	}
}

func buildFinding(target core.Target, note string, isDLMS bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 75, // smart meters with kinetic effects on supply (disconnect/reconnect breakers)
		"exposure":      70,
		"auth_state":    85, // DLMS supports HLS authentication but unauth probes still respond
		"capability":    30,
		"impact_class":  65, // billing accuracy + privacy + remote disconnect of supply
		"cve_exposure":  0,
	}
	if isDLMS {
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
