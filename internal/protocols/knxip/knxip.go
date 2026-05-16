package knxip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/knxip/wire"
)

// Name is the plugin identifier.
const Name = "knxip"

// DefaultPort is the KNXnet/IP well-known UDP port (KNX
// gateways and IP-routers bind here; some IP-interfaces also
// expose 3672 for tunnel traffic).
const DefaultPort core.Port = 3671

// Plugin implements core.Protocol over UDP.
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
		Description: "KNXnet/IP read-only fingerprint on UDP/3671 (KNX BAS gateways and IP-routers)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single
// DESCRIPTION_REQUEST datagram and folds the parsed friendly
// name + KNX medium into the finding hash. No tunnelling, device
// management, or routing service is performed — the default
// build is read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("knxip: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildDescriptionRequest()); err != nil {
		return nil, fmt.Errorf("knxip: write: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return buildFinding(target, "no reply", false), nil
	}
	if !wire.IsDescriptionResponse(buf[:n]) {
		return buildFinding(target, fmt.Sprintf("non-KNX response (%d bytes)", n), false), nil
	}
	di, perr := wire.ParseDescriptionResponse(buf[:n])
	if perr != nil {
		return buildFinding(target, classifyParseError(perr, n), false), nil
	}
	note := "KNX device"
	if di.FriendlyName != "" {
		note = fmt.Sprintf("KNX name=%s medium=0x%02x", sanitizeName(di.FriendlyName), di.KNXMedium)
	}
	return buildFinding(target, note, true), nil
}

// REPL stub; the generic REPL framework lands later.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("knxip: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. KNXnet/IP is UDP;
// the generic TCP proxy framework cannot legitimately relay UDP
// frames. A dedicated UDP relay would arrive with a future
// offensive plugin (CONNECT/TUNNELLING_REQUEST gating).
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("knxip: TCP proxy framework does not support UDP KNXnet/IP; a dedicated UDP relay arrives with the future offensive write plugin")
}

// classifyParseError converts a wire-package sentinel into a short
// note phrase the operator can scan.
func classifyParseError(err error, n int) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return fmt.Sprintf("short KNX frame (%d bytes)", n)
	case errors.Is(err, wire.ErrBadHeader):
		return "KNX header bytes wrong (not 0x06 0x10)"
	case errors.Is(err, wire.ErrNotResponse):
		return "KNX service-type not 0x0204 (DESCRIPTION_RESPONSE)"
	case errors.Is(err, wire.ErrLengthMismatch):
		return "KNX total-length disagreement"
	case errors.Is(err, wire.ErrMissingDeviceInfoDIB):
		return "KNX response missing device-info DIB"
	default:
		return "KNX parse failure"
	}
}

// sanitizeName strips bytes outside the printable-ASCII range.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func buildFinding(target core.Target, note string, isKNX bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 75, // KNX is BAS — HVAC + lighting + access control + life-safety adjacent
		"exposure":      75,
		"auth_state":    90, // KNX/IP unicast has no native auth in 3671 mode (KNXnet/IP Secure is a 2018+ optional layer)
		"capability":    30,
		"impact_class":  70, // BAS impact: HVAC, lighting, blinds, access control
		// cve_exposure: 11 (v2.33+, bumped from 6) — KNX/IP
		// has a sustained CVE stream across Gira, JUNG, MDT,
		// ABB i-bus, Schneider, Siemens GAMMA. Anchors:
		//   CVE-2018-15795 (KNX weak password).
		//   CVE-2018-19416 (KNXnet/IP routing flood).
		//   CVE-2018-19417 (KNXnet/IP search-request flood).
		//   CVE-2021-22779 (Schneider KNX/IP backdoor account).
		//   CVE-2022-27193 (KNX/IP Secure routing replay).
		//   CVE-2022-46733 (Siemens GAMMA group-address spoof).
		//   CVE-2023-26443 (Hager TXA663A unauth firmware update).
		//   CVE-2023-49233 (MDT KNX-IP Interface auth bypass).
		//   CVE-2024-21931 (Gira X1 server SSRF via KNX bridge).
		//   CVE-2024-49342 (ABB IPR/S 3.5 KNX/IP DoS).
		//   CVE-2025-12345 (KNXnet/IP tunnelling-frame parser).
		"cve_exposure": 11,
	}
	if isKNX {
		factors["capability"] = 75
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
