package tristation

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
	"local/elsereno/internal/netutil"
	"local/elsereno/internal/protocols/tristation/wire"
	"local/elsereno/internal/scoring"
)

// Name is the plugin identifier.
const Name = "tristation"

// ErrNoReply is returned when the controller does not answer a request.
var ErrNoReply = errors.New("tristation: no reply")

// ErrRefused is returned when the controller answers CONNECT with
// anything but CONNECT REPLY (connection limit, access denied, ...).
var ErrRefused = errors.New("tristation: connect refused")

// Plugin implements core.Protocol over UDP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 3 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol. DefaultPort 0 + OptIn keep it out
// of discover/scan: it runs only when named with --plugin tristation.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "TriStation (Triconex SIS) opt-in fingerprint on UDP/1502: CONNECT then DISCONNECT, no command issued (run with --plugin tristation --target host:1502)",
		DefaultPort: 0,
		Build:       "default",
		Version:     "v1",
		OptIn:       true,
	}
}

// Probe implements core.Protocol: CONNECT REQUEST, classify, DISCONNECT.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	s, err := p.Open(ctx, net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port)))
	switch {
	case errors.Is(err, ErrNoReply):
		return buildFinding(target, "no reply to CONNECT", false), nil
	case errors.Is(err, ErrRefused):
		return buildFinding(target, err.Error(), true), nil
	case err != nil:
		return buildFinding(target, err.Error(), false), nil
	}
	s.Close()
	return buildFinding(target, "TriStation CONNECT REPLY", true), nil
}

// Session is an open TriStation connection.
type Session struct {
	conn net.Conn
	io   time.Duration
}

// Open dials addr over UDP and performs the CONNECT handshake.
func (p *Plugin) Open(ctx context.Context, addr string) (*Session, error) {
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("tristation: dial %s: %w", addr, err)
	}
	s := &Session{conn: conn, io: p.IOTimeout}
	req := wire.BuildConnect()
	reply, err := s.roundTrip(req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if netutil.IsEcho(req, reply) {
		_ = conn.Close()
		return nil, fmt.Errorf("reply echoes the CONNECT probe (not TriStation)")
	}
	f, err := wire.Parse(reply)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("non-TriStation reply: %w", err)
	}
	if f.Opcode != wire.OpConnectReply {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %s", ErrRefused, wire.OpcodeName(f.Opcode))
	}
	return s, nil
}

// Status sends one read-only Get CP status command and decodes the reply.
func (s *Session) Status() (wire.CPStatus, error) {
	reply, err := s.roundTrip(wire.BuildGetCPStatus(0))
	if err != nil {
		return wire.CPStatus{}, err
	}
	return wire.ParseCPStatus(reply)
}

// Close sends DISCONNECT (best effort) and closes the socket.
func (s *Session) Close() {
	_ = s.conn.SetDeadline(time.Now().Add(s.io))
	_, _ = s.conn.Write(wire.BuildDisconnect())
	_ = s.conn.Close()
}

func (s *Session) roundTrip(req []byte) ([]byte, error) {
	_ = s.conn.SetDeadline(time.Now().Add(s.io))
	if _, err := s.conn.Write(req); err != nil {
		return nil, fmt.Errorf("tristation: write: %w", err)
	}
	buf := make([]byte, 1500)
	n, err := s.conn.Read(buf)
	if err != nil || n == 0 {
		return nil, ErrNoReply
	}
	return buf[:n], nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("tristation: probe-only plugin has no REPL")
}

// ProxyHandler returns a fail-closed handler: TriStation is UDP and a
// relay to a safety controller is out of scope.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("tristation: no proxy for a safety controller protocol (UDP, and relaying to an SIS is out of scope)")
}

func buildFinding(target core.Target, note string, isTriStation bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 95, // safety instrumented system: the last protection layer
		"exposure":      75,
		"auth_state":    85, // the protocol has no authentication; only the key switch gates writes
		"capability":    30,
		"impact_class":  95, // loss of safety function: physical harm (TRITON, 2017)
		"cve_exposure":  10, // qualitative: no product-keyed CVE is attributable from CONNECT alone (PITF-070)
	}
	if isTriStation {
		factors["capability"] = 80
	}
	score := scoring.ScoreDefault(factors)
	return &core.Finding{
		ID:          core.UUID(hex.EncodeToString(hash(target, note)[:16])),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hash(target, note),
	}
}

func hash(target core.Target, note string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	_, _ = h.Write([]byte(note))
	return h.Sum(nil)
}

func portBytes(p core.Port) [2]byte {
	return [2]byte{byte(uint16(p) >> 8 & 0xff), byte(uint16(p) & 0xff)}
}
