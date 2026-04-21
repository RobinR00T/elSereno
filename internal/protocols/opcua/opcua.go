package opcua

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
	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/internal/render"
)

// Name is the plugin identifier.
const Name = "opcua"

// DefaultPort is the well-known UA-TCP port.
const DefaultPort core.Port = 4840

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
		Description: "OPC UA TCP (Part 6) fingerprint on 4840 — sends Hello, classifies ACK/ERR response",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a UA-TCP HEL with a
// synthetic endpoint URL, then reads one frame. The first
// response bytes are enough to distinguish ACK/ERR/not-UA; the
// probe does NOT continue into SecureChannel establishment.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("opcua: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if err := sendHello(conn, addr); err != nil {
		return nil, err
	}
	h, body, rawErr := readFrame(conn)
	if rawErr != nil {
		// rawErr carries the already-rendered SafeBytes snippet
		// for the non-UA or short-read paths.
		return buildFinding(target, rawErr.note, false, "", rawErr.snippet), nil
	}
	return classifyFrame(target, h, body), nil
}

// rawFrameErr is the degraded-path error type from readFrame —
// not strictly an "error" because the caller still wants to
// emit a finding, just without any UA-layer detail.
type rawFrameErr struct {
	note    string
	snippet string
}

func (e *rawFrameErr) Error() string { return e.note }

// sendHello crafts and writes the client Hello.
func sendHello(conn net.Conn, addr string) error {
	hello := wire.EncodeHello(wire.Hello{
		ReceiveBufSize: 65536,
		SendBufSize:    65536,
		MaxMessageSize: 16777216,
		MaxChunkCount:  5000,
		EndpointURL:    fmt.Sprintf("opc.tcp://%s/", addr),
	})
	if _, err := conn.Write(hello); err != nil {
		return fmt.Errorf("opcua: write hello: %w", err)
	}
	return nil
}

// readFrame pulls one UA-TCP frame off conn. Returns the parsed
// header + body on success, or a rawFrameErr describing the
// degraded classification (no-response / non-UA bytes) when the
// response doesn't parse.
func readFrame(conn net.Conn) (wire.Header, []byte, *rawFrameErr) {
	buf := make([]byte, 4096)
	n, _ := io.ReadFull(conn, buf[:wire.HeaderSize])
	if n < wire.HeaderSize {
		return wire.Header{}, nil, &rawFrameErr{note: "no-response"}
	}
	h, err := wire.ParseHeader(buf[:wire.HeaderSize])
	if err != nil {
		return wire.Header{}, nil, &rawFrameErr{
			note:    "non-ua-bytes",
			snippet: render.SafeBytes(buf[:n]),
		}
	}
	if h.Length <= wire.HeaderSize {
		return h, nil, nil
	}
	remaining := int(h.Length) - wire.HeaderSize
	if remaining > len(buf)-wire.HeaderSize {
		remaining = len(buf) - wire.HeaderSize
	}
	got, _ := io.ReadFull(conn, buf[wire.HeaderSize:wire.HeaderSize+remaining])
	return h, buf[wire.HeaderSize : wire.HeaderSize+got], nil
}

// classifyFrame maps the parsed header + body into a Finding.
// Splitting this out of Probe keeps the TCP plumbing and the
// wire-level classification at different levels of abstraction.
func classifyFrame(target core.Target, h wire.Header, body []byte) *core.Finding {
	switch h.Type {
	case wire.MessageAck:
		ack, err := wire.ParseAcknowledge(body)
		if err != nil {
			return buildFinding(target, "ack-malformed", true, "", err.Error())
		}
		note := fmt.Sprintf("ua-ack version=%d recv=%d send=%d",
			ack.Version, ack.ReceiveBufSize, ack.SendBufSize)
		return buildFinding(target, "ua-ack", true, note, "")
	case wire.MessageError:
		e, err := wire.ParseError(body)
		if err != nil {
			return buildFinding(target, "ua-err-malformed", true, "", err.Error())
		}
		note := fmt.Sprintf("ua-err code=0x%08x reason=%q", e.Code, render.SafeBytes([]byte(e.Reason)))
		return buildFinding(target, "ua-err", true, note, "")
	default:
		return buildFinding(target, "ua-unexpected", true, fmt.Sprintf("ua-%s", h.Type), "")
	}
}

// REPL stub — same pattern as fox; the generic framework
// replaces this in F4 chunk 2.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return errors.New("opcua: REPL arrives with the generic framework")
}

// ProxyHandler returns the default deny-all proxy. Any client
// bytes going upstream could (a) establish a SecureChannel, (b)
// attempt a Session + ActivateSession, (c) subsequently issue
// Write or Call service requests that mutate PLC state. Until
// v1.2 ships the offensive/write/opcua WriteGatedHandler, the
// default proxy drops the connection.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

// Handle returns a single UA-TCP ERR frame (code
// Bad_ResourceLimitsExceeded + reason "proxy refuses client
// input") and closes the connection. A UA-native refusal means
// real clients get a parseable rejection rather than a raw TCP
// RST.
func (denyAll) Handle(_ context.Context, client, _ io.ReadWriter) error {
	_, _ = client.Write(refusalFrame)
	return errors.New("opcua: proxy refuses client input by default (use -tags offensive + triple confirm)")
}

// refusalFrame is the fixed ERR frame the default proxy emits.
// Pre-computed at init so the hot path is a single Write().
// Wire layout:
//
//	[0..3]   "ERR" + 'F'
//	[4..7]   LE uint32 total length (header + body)
//	[8..11]  LE uint32 status = 0x80A40000 (Bad_ResourceLimitsExceeded)
//	[12..15] LE uint32 reason length = 6
//	[16..21] "denied"
var refusalFrame = buildRefusalFrame()

func buildRefusalFrame() []byte {
	body := []byte{
		0x00, 0x00, 0xA4, 0x80, // status 0x80A40000 (LE)
		0x06, 0x00, 0x00, 0x00, // reason length = 6
		'd', 'e', 'n', 'i', 'e', 'd',
	}
	// #nosec G115 — total length is a const 22 bytes by construction
	l := uint32(wire.HeaderSize + len(body))
	frame := make([]byte, wire.HeaderSize+len(body))
	copy(frame[0:3], "ERR")
	frame[3] = 'F'
	frame[4] = byte(l & 0xFF)
	frame[5] = byte((l >> 8) & 0xFF)
	frame[6] = byte((l >> 16) & 0xFF)
	frame[7] = byte((l >> 24) & 0xFF)
	copy(frame[wire.HeaderSize:], body)
	return frame
}

// buildFinding renders a core.Finding from the probe outcome.
// uaTCP is the high-order signal: "did this service speak
// UA-TCP at all". extra is optional detail (frame hex, error
// reason) surfaced in the Finding payload for operator triage.
func buildFinding(target core.Target, note string, uaTCP bool, detail, extra string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85, // ICS middleware, widely deployed
		"exposure":      75,
		"auth_state":    60, // anonymous HEL is always allowed
		"capability":    30, // probe-only; write gating is v1.2
		"impact_class":  85, // PLC control plane
		"cve_exposure":  0,
	}
	if uaTCP {
		factors["capability"] = 60
	}
	score := scoreFor(factors)
	_ = detail // kept for forward-compatible payload building
	_ = extra
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
