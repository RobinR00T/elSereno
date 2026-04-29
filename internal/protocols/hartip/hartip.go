package hartip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/hartip/wire"
)

// Name is the plugin identifier.
const Name = "hartip"

// DefaultPort is the well-known port.
const DefaultPort core.Port = 5094

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
		Description: "HART-IP (process instrumentation) session-initiate fingerprint on port 5094",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("hartip: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))
	if _, err := conn.Write(wire.BuildSessionInitiate(1)); err != nil {
		return nil, fmt.Errorf("hartip: write: %w", err)
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	h, perr := wire.ParseHeader(buf[:n])
	isOK := perr == nil && h.MsgType == wire.MsgResponse
	note := "silent"
	if isOK {
		note = fmt.Sprintf("HART-IP response msg_id=%d status=%d", h.MsgID, h.Status)
	}
	return buildFinding(target, note, isOK), nil
}

// REPL stub until the generic REPL framework lands.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("hartip: REPL arrives with the generic framework")
}

// ProxyHandler returns the default HART-IP proxy, which refuses
// TokenPassPDU messages (the envelope carrying an inner HART command
// that may be a write) with a session-close response carrying
// status 0x04 "Unsupported command" (ADR-040). Session-management
// messages forward untouched so the HART-IP lifecycle completes.
// The offensive build substitutes a handler that parses the inner
// HART command and routes writes through the triple-confirm
// wrapper.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &writeBanHandler{} }

type writeBanHandler struct{}

func (writeBanHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	errs := make(chan error, 2)
	go func() { errs <- forwardFiltered(client, upstream, client) }()
	go func() {
		_, err := io.Copy(client, upstream)
		errs <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

// forwardFiltered reads one HART-IP packet at a time.
func forwardFiltered(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	buf := make([]byte, wire.HeaderLen)
	for {
		if _, err := io.ReadFull(client, buf); err != nil {
			return err
		}
		h, err := wire.ParseHeader(buf)
		if err != nil {
			return err
		}
		bodyLen := int(h.ByteCount) - wire.HeaderLen
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(client, body); err != nil {
				return err
			}
		}
		if wire.Classify(h) == wire.CategoryRead {
			if _, werr := upstream.Write(buf); werr != nil {
				return werr
			}
			if bodyLen > 0 {
				if _, werr := upstream.Write(body); werr != nil {
					return werr
				}
			}
			continue
		}
		if _, werr := clientWriter.Write(wire.BuildRefusal(h)); werr != nil {
			return werr
		}
	}
}

func buildFinding(target core.Target, note string, isOK bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80,
		"exposure":      75,
		"auth_state":    80,
		"capability":    30,
		"impact_class":  80,
		// cve_exposure 7: CVE-2014-7494 (Honeywell XYR 6000),
		// CVE-2015-7905 (Yokogawa STARDOM HART), CVE-2019-9869
		// (Phoenix Contact HART-IP) — modest sensor-network
		// surface, less broad than DNP3/IEC104 but real.
		"cve_exposure": 7,
	}
	if isOK {
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
