package modbus

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
	"local/elsereno/internal/protocols/modbus/wire"
)

// Name is the plugin identifier.
const Name = "modbus"

// DefaultPort is the well-known Modbus/TCP port.
const DefaultPort core.Port = 502

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with conservative timeouts.
func Default() *Plugin {
	return &Plugin{
		DialTimeout: 5 * time.Second,
		IOTimeout:   5 * time.Second,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "Modbus/TCP read-only probe + device-ID fingerprint + proxy with write-ban",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe sends a minimal Read Coils (FC 1) and an opportunistic Read
// Device Identification (FC 43/14). It emits a single Finding
// summarising what the target revealed.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("modbus: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	note, vendor, product, revision := probeStage(conn)
	return buildFinding(target, note, vendor, product, revision), nil
}

// REPL is not yet wired; the generic REPL framework lands in F4.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("modbus: REPL binding arrives with the generic REPL in F4")
}

// ProxyHandler returns the read-only Modbus proxy.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &proxyHandler{} }

// proxyHandler enforces the read-only policy at the wire layer. Every
// client frame whose FunctionCode classifies as CategoryWrite (or MEI
// sub-code != 14) is turned around with an IllegalFunction exception.
type proxyHandler struct{}

// Handle implements core.ProxyHandler.
func (h *proxyHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	errs := make(chan error, 2)

	// client -> upstream: veto per-frame. When a frame is blocked,
	// we write the exception response straight back to the client.
	go func() {
		errs <- forwardFiltered(client, upstream, client)
	}()
	// upstream -> client: forward untouched (findings/evidence
	// capture hooks into the F3 proxy framework).
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

// forwardFiltered parses each client frame, forwards reads to
// `upstream`, and short-circuits writes with an IllegalFunction
// exception sent back via `clientWriter`.
func forwardFiltered(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		frame, err := wire.ReadFrame(client)
		if err != nil {
			return err
		}
		if shouldBlock(frame) {
			resp := exceptionResponse(frame, wire.ExIllegalFunction)
			if err := wire.WriteFrame(clientWriter, resp); err != nil {
				return err
			}
			continue
		}
		if err := wire.WriteFrame(upstream, frame); err != nil {
			return err
		}
	}
}

// shouldBlock returns true when the frame would mutate state. The
// policy: any CategoryWrite; MEI (FC 43) sub-code != 14 (Read Device
// Identification); unknown FCs are conservatively blocked in
// read-only mode.
func shouldBlock(f wire.Frame) bool {
	if f.IsExceptionFrame() {
		return false
	}
	fc := f.FunctionCode()
	cat := wire.Classify(fc)
	switch cat {
	case wire.CategoryRead:
		return false
	case wire.CategoryWrite:
		return true
	case wire.CategoryMEI:
		// Sub-code 14 (0x0E) == Read Device Identification. Anything
		// shorter or with a different sub-code is refused.
		return len(f.PDU) < 2 || f.PDU[1] != 0x0E
	case wire.CategoryDiagnostic:
		return false // F5 will tighten this with per-sub-code rules.
	case wire.CategoryUnknown:
		return true
	}
	return true
}

// exceptionResponse builds a Modbus exception response for `req`.
// The response FC is req's FC | 0x80; the PDU carries the exception
// code as its second byte.
func exceptionResponse(req wire.Frame, code wire.ExceptionCode) wire.Frame {
	fc := uint8(req.FunctionCode()) | 0x80
	return wire.Frame{
		MBAP: wire.MBAP{
			TxID:     req.MBAP.TxID,
			Protocol: wire.ProtocolID,
			Unit:     req.MBAP.Unit,
		},
		PDU: []byte{fc, uint8(code)},
	}
}

// probeStage runs the two-phase probe. Returns (note, vendor,
// product, revision); empty strings if unavailable.
func probeStage(conn net.Conn) (note, vendor, product, revision string) {
	// Phase 1: minimal Read Coils.
	req := wire.BuildReadCoilsRequest(0x0001, 0x01)
	if err := wire.WriteFrame(conn, req); err != nil {
		return fmt.Sprintf("write req: %v", err), "", "", ""
	}
	resp, err := wire.ReadFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return "silent close on read coils", "", "", ""
		}
		return fmt.Sprintf("read resp: %v", err), "", "", ""
	}
	if ec, isEx := resp.ExceptionCode(); isEx {
		note = fmt.Sprintf("exception on FC1: 0x%02x", uint8(ec))
	} else if resp.FunctionCode() == wire.FCReadCoils {
		note = "read-coils accepted"
	} else {
		note = fmt.Sprintf("unexpected FC 0x%02x on FC1", uint8(resp.FunctionCode()))
	}

	// Phase 2: FC 43/14 Read Device Identification (best-effort).
	if v, p, rev, err := probeDeviceID(conn); err == nil {
		vendor, product, revision = v, p, rev
	}
	return note, vendor, product, revision
}

// probeDeviceID issues FC 43 sub-code 14 and returns the three basic
// objects when available.
func probeDeviceID(conn net.Conn) (vendor, product, revision string, err error) {
	req := wire.BuildReadDeviceIDRequest(0x0002, 0x01)
	if err := wire.WriteFrame(conn, req); err != nil {
		return "", "", "", err
	}
	resp, err := wire.ReadFrame(conn)
	if err != nil {
		return "", "", "", err
	}
	if resp.IsExceptionFrame() {
		return "", "", "", fmt.Errorf("fc43 not supported")
	}
	if resp.FunctionCode() != wire.FCEncapsulatedInterface {
		return "", "", "", fmt.Errorf("unexpected FC 0x%02x", uint8(resp.FunctionCode()))
	}
	objs, err := wire.DeviceIDObjects(resp.PDU)
	if err != nil {
		return "", "", "", err
	}
	return objs[0x00], objs[0x01], objs[0x02], nil
}

// buildFinding scores the finding based on what the probe revealed.
func buildFinding(target core.Target, note, vendor, product, revision string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85, // Modbus/TCP exposes OT control paths.
		"exposure":      80,
		"auth_state":    90, // Modbus has no native auth.
		"capability":    60, // read-confirmed devices surface state.
		"impact_class":  70,
		"cve_exposure":  0,
	}
	score := scoreFor(factors)
	detail := note
	if vendor != "" || product != "" {
		detail += fmt.Sprintf(" vendor=%q product=%q rev=%q", vendor, product, revision)
	}
	return &core.Finding{
		ID:          hashID(target, detail),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, detail),
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

// portBytes splits a uint16 port into (hi, lo) — same pattern as
// xot/atmodem: avoid a uint16->byte conversion that gosec flags.
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
