package enip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/enip/wire"
)

// Name is the plugin identifier.
const Name = "enip"

// DefaultPort is the EtherNet/IP well-known port.
const DefaultPort core.Port = 44818

// Plugin implements core.Protocol.
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
		Description: "EtherNet/IP CIP ListIdentity read-only fingerprint on port 44818",
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
		return nil, fmt.Errorf("enip: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildListIdentity()); err != nil {
		return nil, fmt.Errorf("enip: write: %w", err)
	}
	hdr, body, err := wire.ReadPacket(conn)
	if err != nil {
		return buildFinding(target, fmt.Sprintf("read: %v", err), nil), nil
	}
	if hdr.Command != wire.CmdListIdentity {
		return buildFinding(target, fmt.Sprintf("unexpected cmd 0x%04x", hdr.Command), nil), nil
	}
	it, perr := wire.ParseListIdentity(body)
	if perr != nil {
		return buildFinding(target, fmt.Sprintf("body parse: %v", perr), nil), nil
	}
	return buildFinding(target, fmt.Sprintf("ListIdentity: vendor=%d product=%q", it.VendorID, it.ProductName), &it), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("enip: REPL arrives with the generic framework")
}

// ProxyHandler returns the default ENIP proxy, which refuses
// SendRRData / SendUnitData (the envelopes carrying CIP service
// requests — and therefore the vector for writes) with an
// encapsulation reply status=0x0001 ("Invalid or unsupported
// command"). Listing and session-management commands forward as-is.
// The offensive build substitutes a CIP-service-aware handler that
// routes mutating services through the triple-confirm wrapper.
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

// forwardFiltered reads one EIP packet at a time. CategoryRead
// commands forward; everything else is short-circuited with a
// protocol-native refusal.
func forwardFiltered(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		hdr, body, err := wire.ReadPacket(client)
		if err != nil {
			return err
		}
		if wire.Classify(hdr.Command) == wire.CategoryRead {
			buf := wire.MarshalHeader(hdr)
			if _, werr := upstream.Write(buf[:]); werr != nil {
				return werr
			}
			if len(body) > 0 {
				if _, werr := upstream.Write(body); werr != nil {
					return werr
				}
			}
			continue
		}
		if _, werr := clientWriter.Write(wire.BuildRefusal(hdr)); werr != nil {
			return werr
		}
	}
}

func buildFinding(target core.Target, note string, it *wire.IdentityItem) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85,
		"exposure":      80,
		"auth_state":    85,
		"capability":    30,
		"impact_class":  80,
		"cve_exposure":  0,
	}
	if it != nil {
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
