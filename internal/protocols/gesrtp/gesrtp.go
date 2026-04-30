package gesrtp

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
	"local/elsereno/internal/protocols/gesrtp/wire"
)

// Name is the plugin identifier.
const Name = "gesrtp"

// DefaultPort is the GE-SRTP TCP well-known port. Some PACSystems
// installations also bind 18246 for a backup/extended frame; we
// only probe the canonical 18245.
const DefaultPort core.Port = 18245

// Plugin implements core.Protocol over TCP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts. SRTP CONNECTION
// INIT is unannounced — no banner, no negotiation — so a single
// round-trip is enough to fingerprint.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "GE-SRTP read-only fingerprint on TCP/18245 (GE Fanuc / Emerson PACSystems / Series 90 PLCs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single CONNECTION INIT
// 56-byte mailbox, reads up to 64 bytes, and classifies the
// response. The CPU model identification request (service code
// 0x21) is deferred to a future cycle that can carry test vectors
// against real PLCs — public protocol documentation is sparse and
// the connection-init classifier is the safest reliable
// fingerprint.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("gesrtp: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildConnectionInit()); err != nil {
		return nil, fmt.Errorf("gesrtp: write: %w", err)
	}

	buf := make([]byte, 64)
	n, err := io.ReadFull(conn, buf[:wire.MailboxLen])
	if err != nil {
		return buildFinding(target, "no usable reply", false, ""), nil
	}
	if cerr := wire.ClassifyResponse(buf[:n]); cerr != nil {
		return buildFinding(target, classifyParseError(cerr, n), false, ""), nil
	}
	// v1.21 chunk 4: scan the connection-init response payload
	// for an embedded GE PLC model hint (IC693 / IC695 / IC697 /
	// IC200 / RX3i / RX7i / PACSystems family). When present,
	// fold the hint into the finding note and lift the capability
	// factor.
	hint := wire.ExtractModelHint(buf[:n])
	if hint != "" {
		return buildFinding(target, "SRTP model="+hint, true, hint), nil
	}
	return buildFinding(target, "SRTP mailbox response", true, ""), nil
}

// REPL stub; the generic REPL framework lands later. A future
// REPL would expose the connection-init response payload (packet
// number, sequence number, version flags) and let operators issue
// service-code-0x21 reads against test PLCs.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("gesrtp: REPL arrives with the generic framework")
}

// ProxyHandler returns a wire-layer write-ban handler. SRTP is
// TCP, so the generic proxy framework applies — but every SRTP
// service request is a potential write target (memory writes,
// program block writes, RUN/STOP transitions). The default-build
// proxy reads the first 56-byte mailbox from the client and
// replies with a 56-byte mailbox response carrying byte 0 = 0x03
// + a single non-zero byte at offset 42 (status / minor error
// indicator) — close enough to the protocol's "request denied"
// idiom that compatible clients will move on rather than
// reconnect. It does NOT forward to upstream — defence-in-depth
// fail-closed pattern matching the Modbus / S7 / EtherNet/IP
// proxy idioms.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &writeBanHandler{} }

type writeBanHandler struct{}

func (writeBanHandler) Handle(ctx context.Context, client, _ io.ReadWriter) error {
	// Read the 56-byte mailbox from the client.
	hdr := make([]byte, wire.MailboxLen)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return err
	}
	// Reply with a 56-byte mailbox: type byte 0x03 (response),
	// byte 42 = 0x01 (a non-zero "status / minor error" indicator
	// in the published reverse-engineering notes — compatible
	// clients treat this as "request not honoured" and back off
	// rather than retry).
	resp := make([]byte, wire.MailboxLen)
	resp[0] = wire.TypeResponse
	resp[42] = 0x01
	if _, err := client.Write(resp); err != nil {
		return err
	}
	// Honour ctx cancellation so a parent timeout closes us.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

// classifyParseError converts a wire-package sentinel into a short
// note phrase the operator can scan. n is the response length
// (used when the frame failed length validation).
func classifyParseError(err error, n int) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return fmt.Sprintf("short SRTP frame (%d bytes)", n)
	case errors.Is(err, wire.ErrNotResponse):
		return "SRTP response type byte not 0x03"
	default:
		return "SRTP parse failure"
	}
}

// buildFinding builds the SRTP finding. modelHint, when non-
// empty, both folds into the finding hash via note (already done
// by the caller) and lifts capability from 70 to 75 — the
// extracted hint is real, decoded, actionable model info, the
// same delta finsudp/slmp get for their parsed model strings.
func buildFinding(target core.Target, note string, isSRTP bool, modelHint string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // legacy ICS, no auth
		"exposure":      75,
		"auth_state":    95, // SRTP has no authentication
		"capability":    30,
		"impact_class":  75, // factory-floor PLCs
		// cve_exposure: 5 — sparse but high-impact GE-IP / Mark
		// VIe family. Anchor CVEs:
		//   CVE-2018-19003 (GE-IP / Mark VIe firmware download fault).
		//   CVE-2018-19010 (GE PACSystems RX3i memory leak / DoS).
		//   CVE-2022-23410 (Emerson PACSystems CPL410 / RX3i auth).
		"cve_exposure": 5,
	}
	switch {
	case isSRTP && modelHint != "":
		factors["capability"] = 75
	case isSRTP:
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
