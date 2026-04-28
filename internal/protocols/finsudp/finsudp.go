package finsudp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/finsudp/wire"
)

// Name is the plugin identifier.
const Name = "finsudp"

// DefaultPort is the FINS UDP well-known port (Omron CJ/CS/CP/NJ/NX
// CPUs and many compatible HMIs bind here).
const DefaultPort core.Port = 9600

// Plugin implements core.Protocol over UDP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts. UDP probes are
// punchy: a single round-trip is enough to fingerprint, so 3 s
// covers WAN-scale latency without lingering on dead ports.
func Default() *Plugin {
	return &Plugin{DialTimeout: 3 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "Omron FINS read-only fingerprint on UDP/9600 (CJ/CS/CP/NJ/NX CPUs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single CONTROLLER DATA
// READ datagram, parses the reply, and folds the controller model
// into the finding hash. No memory-area read or write is performed
// — the default build is read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("finsudp: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	sid, err := newSID()
	if err != nil {
		return nil, fmt.Errorf("finsudp: sid: %w", err)
	}
	if _, err := conn.Write(wire.BuildControllerDataRead(sid)); err != nil {
		return nil, fmt.Errorf("finsudp: write: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return buildFinding(target, "no reply", false), nil
	}
	if !wire.IsResponse(buf[:n]) {
		return buildFinding(target, fmt.Sprintf("non-FINS response (%d bytes)", n), false), nil
	}
	cd, perr := wire.ParseControllerDataRead(buf[:n], sid)
	if perr != nil {
		return buildFinding(target, classifyParseError(perr, n), false), nil
	}
	note := "FINS controller-data"
	if cd.Model != "" {
		note = "FINS model=" + sanitizeModel(cd.Model)
	}
	return buildFinding(target, note, true), nil
}

// REPL stub; the generic REPL framework lands later. Operators who
// want to inspect the parsed ControllerData can read the finding's
// note (model) until the REPL ships.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("finsudp: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. FINS is UDP; the
// generic TCP proxy framework cannot legitimately relay UDP frames.
// A dedicated UDP relay would arrive with a future offensive-build
// FINS write plugin; until then, refuse the session immediately so
// operators don't accidentally shuttle bytes that aren't FINS.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("finsudp: TCP proxy framework does not support UDP FINS; a dedicated UDP relay arrives with the offensive write plugin")
}

// classifyParseError converts a wire-package sentinel into a short
// note phrase the operator can scan. n is the response length (used
// when the frame failed length validation).
func classifyParseError(err error, n int) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return fmt.Sprintf("short FINS frame (%d bytes)", n)
	case errors.Is(err, wire.ErrServiceMismatch):
		return "FINS SID echo mismatch"
	case errors.Is(err, wire.ErrEndCodeNonZero):
		return "FINS end-code non-zero (refusal)"
	case errors.Is(err, wire.ErrNotResponse):
		return "FINS frame not a response or wrong MRC/SRC"
	default:
		return "FINS parse failure"
	}
}

// sanitizeModel strips bytes outside the printable-ASCII range so a
// model field cannot smuggle ANSI escapes or control characters into
// the finding hash payload (downstream consumers render the note via
// SafeBytes anyway, but defence-in-depth is cheap).
func sanitizeModel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// newSID returns a non-zero random SID. Zero is a valid wire SID but
// callers like to reserve it for "uninitialised", so we keep it
// out of the request space.
func newSID() (byte, error) {
	var buf [1]byte
	for i := 0; i < 4; i++ {
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		if buf[0] != 0 {
			return buf[0], nil
		}
	}
	return 1, nil
}

func buildFinding(target core.Target, note string, isFINS bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // legacy ICS, no auth, write services on same port
		"exposure":      80,
		"auth_state":    95, // FINS has no authentication
		"capability":    30,
		"impact_class":  75, // factory-floor PLCs control real machinery
		"cve_exposure":  0,
	}
	if isFINS {
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
