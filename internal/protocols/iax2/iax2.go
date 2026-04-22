package iax2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/iax2/wire"
)

// Name is the plugin identifier.
const Name = "iax2"

// DefaultPort is the well-known IAX2 port.
const DefaultPort core.Port = 4569

// Plugin implements core.Protocol for IAX2 (Asterisk native
// binary protocol over UDP).
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{
		DialTimeout: 3 * time.Second,
		IOTimeout:   2 * time.Second,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "Asterisk IAX2 (RFC 5456) probe on UDP/4569 — sends NEW, classifies ACCEPT / AUTHREQ / REJECT reply",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("iax2: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	srcCall := randomCallNumber()
	if _, err := conn.Write(wire.BuildNEW(srcCall)); err != nil {
		return nil, fmt.Errorf("iax2: write NEW: %w", err)
	}
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n < wire.HeaderLen {
		return buildFinding(target, "no-response", false, 0), nil
	}
	h, err := wire.ParseHeader(buf[:n])
	if err != nil {
		// Genuine IAX2 mini-frames are exactly 4 bytes; anything
		// else that trips ErrMiniFrame is not-IAX2 payload that
		// happened to have byte[0]&0x80 == 0 (e.g. an HTTP error
		// reply starting with 'H' = 0x48).
		if errors.Is(err, wire.ErrMiniFrame) && n == 4 {
			return buildFinding(target, "iax2-miniframe", true, 0), nil
		}
		return buildFinding(target, "non-iax2-bytes", false, 0), nil
	}
	if !h.IsIAXReply() {
		return buildFinding(target, "non-iax2-frame", false, 0), nil
	}
	note := subclassNote(h.Subclass)
	// Best-effort polite close: if the remote accepted, send
	// HANGUP so we don't leave a stale call entry in their
	// dialogue table.
	if h.Subclass == byte(wire.IAXAccept) {
		_, _ = conn.Write(wire.BuildHANGUP(srcCall, h.SrcCallNum, 1, 1))
	}
	return buildFinding(target, note, true, h.Subclass), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return errors.New("iax2: REPL arrives with the generic framework")
}

// ProxyHandler returns a deny-all proxy. IAX2 proxying would
// require a full IE parser + tag-rewrite, deliberately out of
// scope. The default build refuses every client byte.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &denyAll{} }

type denyAll struct{}

// Handle on IAX2 writes nothing back (UDP; there's no
// stream-level refusal) and returns an error immediately.
func (denyAll) Handle(_ context.Context, _, _ io.ReadWriter) error {
	return errors.New("iax2: proxy refuses client input by default")
}

// subclassNote returns a short tag for the finding's note
// field based on the IAX subclass.
func subclassNote(sub uint8) string {
	switch wire.IAXSubclass(sub) { //nolint:exhaustive // only tag the subclasses we care about; rest fall through to "iax2-other"
	case wire.IAXAccept:
		return "iax2-accept"
	case wire.IAXAuthReq:
		return "iax2-authreq"
	case wire.IAXReject:
		return "iax2-reject"
	case wire.IAXHangup:
		return "iax2-hangup"
	case wire.IAXPing, wire.IAXPong:
		return "iax2-pingpong"
	case wire.IAXRegauth, wire.IAXRegack, wire.IAXRegrej:
		return "iax2-reg"
	}
	return "iax2-other"
}

// buildFinding scores the probe outcome. iax2Confirmed=true
// when we're sure the remote is Asterisk IAX2.
func buildFinding(target core.Target, note string, iax2Confirmed bool, subclass uint8) *core.Finding {
	factors := map[string]int{
		// IAX2 is Asterisk-specific; confirmed = 90 (same as
		// Asterisk SIP fingerprint).
		"protocol_risk": 70,
		"exposure":      80,
		"auth_state":    60,
		"capability":    30,
		"impact_class":  75,
		"cve_exposure":  0,
	}
	if iax2Confirmed {
		factors["protocol_risk"] = 90
		factors["capability"] = 60
	}
	// AUTHREQ means the server asks for credentials — slightly
	// harder to exploit than a fully-open registrar.
	if wire.IAXSubclass(subclass) == wire.IAXAuthReq {
		factors["auth_state"] = 50
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

// randomCallNumber returns a 15-bit call number from crypto/rand.
// IAX2 call numbers are unique per-peer but we don't track state
// across probes — any random value works.
func randomCallNumber() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:]) & 0x7FFF
}
