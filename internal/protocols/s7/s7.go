package s7

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
	"local/elsereno/internal/protocols/s7/wire"
)

// Name is the plugin identifier.
const Name = "s7"

// DefaultPort is the S7 well-known port (TPKT/COTP).
const DefaultPort core.Port = 102

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with conservative timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 5 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "S7comm (Siemens) TPKT/COTP read-only fingerprint on port 102",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe sends a COTP Connection Request wrapped in TPKT and
// classifies the response.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("s7: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if err := wire.WriteTPKT(conn, wire.BuildCOTPConnectionRequest()); err != nil {
		return nil, fmt.Errorf("s7: write CR: %w", err)
	}
	tpkt, err := wire.ReadTPKT(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return buildFinding(target, "silent close", false), nil
		}
		return nil, fmt.Errorf("s7: read: %w", err)
	}
	return buildFinding(target, classify(tpkt.Payload), wire.IsCOTPConfirm(tpkt.Payload)), nil
}

// REPL is planned for F4 chunk 2 (generic REPL framework).
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("s7: REPL arrives with the generic REPL framework")
}

// ProxyHandler returns the default S7 proxy, which refuses writes
// at the wire layer (ADR-040). Every TPKT envelope from the client
// is parsed; the COTP/S7 function code is classified, and any
// CategoryWrite or CategoryUnknown frame is short-circuited with an
// S7 AckData carrying error class 0x85 (Function not allowed). The
// offensive build substitutes WriteGatedHandler for this one to
// route Writes through the triple-confirm wrapper.
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

// forwardFiltered reads client TPKT envelopes one at a time. If the
// frame is a COTP Data PDU carrying an S7 Job with a CategoryRead
// function, it is forwarded to upstream; otherwise a refusal reply
// is sent straight back to the client (clientWriter) and upstream
// never sees the bytes.
func forwardFiltered(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		tpkt, err := wire.ReadTPKT(client)
		if err != nil {
			return err
		}
		if shouldBlock(tpkt.Payload) {
			if err := wire.WriteTPKT(clientWriter, wire.BuildRefusalPayload(cotpDataPayload(tpkt.Payload))); err != nil {
				return err
			}
			continue
		}
		if err := wire.WriteTPKT(upstream, tpkt.Payload); err != nil {
			return err
		}
	}
}

// shouldBlock returns true when the client TPKT carries a COTP Data
// PDU classified as Write or Unknown. Non-Data COTP PDUs (CR, CC,
// DR) are forwarded unchanged so the handshake completes.
func shouldBlock(payload []byte) bool {
	t, ok := wire.COTPType(payload)
	if !ok {
		return true
	}
	if t != wire.COTPData {
		return false
	}
	// S7 PDU starts after COTP header. COTP DT header is 3 bytes
	// (LI + type + TPDU-nr). LI is in payload[0].
	if len(payload) < 3 {
		return true
	}
	li := int(payload[0])
	// LI excludes itself; total COTP header is li + 1.
	s7Start := li + 1
	if s7Start >= len(payload) {
		return true
	}
	fc, ok := wire.ExtractFunctionCode(payload[s7Start:])
	if !ok {
		return true
	}
	switch wire.Classify(fc) {
	case wire.CategoryRead:
		return false
	default:
		return true
	}
}

// cotpDataPayload slices the S7 PDU portion out of a COTP DT TPKT
// payload so the refusal builder can read the request's pduRef.
func cotpDataPayload(payload []byte) []byte {
	if len(payload) < 3 {
		return payload
	}
	li := int(payload[0])
	s7Start := li + 1
	if s7Start >= len(payload) {
		return payload
	}
	return payload[s7Start:]
}

func classify(payload []byte) string {
	t, ok := wire.COTPType(payload)
	if !ok {
		return "empty COTP"
	}
	switch t {
	case wire.COTPConnectionConfirm:
		return "COTP Connection Confirm (S7 family likely)"
	case wire.COTPDisconnectRequest:
		return "COTP Disconnect Request"
	case wire.COTPData:
		return "COTP Data (unexpected for a bare CR probe)"
	default:
		return fmt.Sprintf("COTP type 0x%02x", t)
	}
}

func buildFinding(target core.Target, note string, isConfirm bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85,
		"exposure":      80,
		"auth_state":    85,
		"capability":    30,
		"impact_class":  80, // S7 PLCs drive safety-adjacent processes
		// cve_exposure 14: CVE-2014-2249 (S7-300 stack
		// overflow), CVE-2016-4785 (S7-1500 auth bypass),
		// CVE-2018-13815 (S7-300 PLC crash), and the
		// Stuxnet-era family (CVE-2010-2772) — broadest CVE
		// surface in the ICS plugin set, reflecting Siemens
		// PLC market share + documented exploit history.
		"cve_exposure": 14,
	}
	if isConfirm {
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
