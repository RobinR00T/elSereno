// Package mqtt fingerprints an MQTT broker for exposure: does an
// anonymous client get in, and if so can it subscribe to every topic?
// MQTT is the dominant OT-to-IT / Unified-Namespace bus, and brokers are
// routinely stood up with anonymous access and no ACLs, so "a stranger
// can read the whole plant" is a common, high-impact misconfiguration.
//
// The probe is read-only: it sends CONNECT (anonymous) and, only if that
// is accepted, one SUBSCRIBE to the wildcard `#`, then briefly reads any
// PUBLISH traffic to spot the Sparkplug B namespace. It never PUBLISHes.
package mqtt

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/mqtt/wire"
	"local/elsereno/internal/scoring"
)

// Name is the plugin identifier.
const Name = "mqtt"

// DefaultPort is 1883 (plaintext MQTT). Port 8883 is probed over TLS.
const DefaultPort core.Port = 1883

// tlsPort is the registered MQTT-over-TLS port; the probe wraps the dial
// in TLS when the target port is 8883.
const tlsPort core.Port = 8883

// clientID identifies the probe honestly on the broker (authorised
// scanning; not stealth).
const clientID = "elsereno-recon"

// sparkplugPrefix is the Sparkplug B topic namespace (Eclipse Tahu).
const sparkplugPrefix = "spBv1.0/"

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	// SkipVerify probes self-signed broker certs on 8883 (fingerprint,
	// not trust). Defaults true.
	SkipVerify bool
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 4 * time.Second, SkipVerify: true}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "MQTT broker exposure fingerprint on 1883 (8883 TLS): anonymous CONNECT + wildcard-subscribe + Sparkplug B detection",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// probeResult carries what the exchange learned.
type probeResult struct {
	returnCode byte
	anon       bool
	wildcard   bool
	sparkplug  bool
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	conn, err := p.dial(ctx, addr, target.Port)
	if err != nil {
		return nil, fmt.Errorf("mqtt: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.EncodeConnect(clientID)); err != nil {
		return nil, fmt.Errorf("mqtt: write CONNECT: %w", err)
	}
	b0, payload, err := wire.ReadPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("mqtt: read CONNACK: %w", err)
	}
	if wire.PacketType(b0) != wire.PktCONNACK {
		return nil, nil // not MQTT (or not 3.1.1): stay quiet, avoid noise
	}
	_, code, ok := wire.ParseConnack(payload)
	if !ok {
		return nil, nil
	}

	res := probeResult{returnCode: code, anon: code == wire.ConnAccepted}
	if res.anon {
		res.wildcard, res.sparkplug = p.probeWildcard(conn)
	}
	return buildFinding(target, res), nil
}

// dial opens a TCP (or TLS on 8883) connection to the broker.
func (p *Plugin) dial(ctx context.Context, addr string, port core.Port) (net.Conn, error) {
	d := net.Dialer{Timeout: p.DialTimeout}
	if port == tlsPort {
		td := &tls.Dialer{
			NetDialer: &d,
			// #nosec G402 -- fingerprinting untrusted brokers; we never
			// send credentials and never trust the peer.
			Config: &tls.Config{InsecureSkipVerify: p.SkipVerify, MinVersion: tls.VersionTLS12},
		}
		return td.DialContext(ctx, "tcp", addr)
	}
	return d.DialContext(ctx, "tcp", addr)
}

// probeWildcard subscribes to `#` and, if granted, briefly reads any
// PUBLISH traffic to detect the Sparkplug B namespace. Read-only: it
// never publishes.
func (p *Plugin) probeWildcard(conn net.Conn) (wildcard, sparkplug bool) {
	if _, err := conn.Write(wire.EncodeSubscribe(1, "#")); err != nil {
		return false, false
	}
	b0, payload, err := wire.ReadPacket(conn)
	if err != nil || wire.PacketType(b0) != wire.PktSUBACK {
		return false, false
	}
	granted, ok := wire.ParseSuback(payload)
	if !ok || len(granted) == 0 || granted[0] == wire.SubackFailure {
		return false, false
	}
	wildcard = true

	// Short window to catch live topics (Sparkplug edge nodes publish
	// frequently). Bounded reads; a quiet bus just yields no PUBLISH.
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 16; i++ {
		pb0, ppayload, perr := wire.ReadPacket(conn)
		if perr != nil {
			break
		}
		if wire.PacketType(pb0) != wire.PktPUBLISH {
			continue
		}
		if topic, ok := wire.PublishTopic(ppayload); ok && strings.HasPrefix(topic, sparkplugPrefix) {
			return wildcard, true
		}
	}
	return wildcard, false
}

func buildFinding(target core.Target, r probeResult) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 55,
		"exposure":      70, // a reachable broker is internet/segment-exposed
		"auth_state":    45,
		"capability":    40,
		"impact_class":  60, // OT-to-IT bus; carries process data + commands
		"cve_exposure":  8,
	}
	if r.anon {
		// Anonymous access = the headline misconfiguration.
		factors["auth_state"] = 90
		factors["exposure"] = 85
		factors["capability"] = 65
	}
	if r.wildcard {
		// A stranger can read every topic on the bus.
		factors["capability"] = 85
		factors["impact_class"] = 75
	}
	if r.sparkplug {
		// Confirmed live Sparkplug B: real device/plant data flowing.
		factors["impact_class"] = 85
	}
	score := scoring.ScoreDefault(factors)
	note := fmt.Sprintf("mqtt anon=%t wildcard=%t sparkplug=%t connack=0x%02x", r.anon, r.wildcard, r.sparkplug, r.returnCode)
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

// REPL stub until the generic REPL framework lands.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("mqtt: REPL arrives with the generic framework")
}

// ProxyHandler returns deny-all: an MQTT proxy would let a client
// PUBLISH to control topics through us. Mirrors the opcua/opcuahttps
// deny stance; a gated MQTT proxy (allowlist PUBLISH topics) is vNext.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

func (denyAll) Handle(_ context.Context, _, _ io.ReadWriter) error {
	return fmt.Errorf("mqtt: proxy denies client input by default")
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
