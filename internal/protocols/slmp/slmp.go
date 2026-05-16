package slmp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/slmp/wire"
)

// Name is the plugin identifier.
const Name = "slmp"

// DefaultPort is the SLMP TCP well-known port (Mitsubishi Electric
// iQ-R / iQ-F / Q- / L- / FX-series CPUs and many compatible HMIs
// bind here).
const DefaultPort core.Port = 5007

// Plugin implements core.Protocol over TCP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts. SLMP TCP
// handshakes are unannounced — no banner, no negotiation — so a
// single round-trip is enough to fingerprint.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "MELSEC SLMP read-only fingerprint on TCP/5007 (Mitsubishi iQ-R/iQ-F/Q/L/FX CPUs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a single READ CPU MODEL
// NAME 3E request, parses the reply, and folds the controller
// model into the finding hash. No memory-area read or write is
// performed — the default build is read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("slmp: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildReadCPUModelName()); err != nil {
		return nil, fmt.Errorf("slmp: write: %w", err)
	}

	buf := make([]byte, 256)
	n, err := io.ReadFull(conn, buf[:wire.HeaderLenResponse+2])
	if err != nil {
		// Couldn't even read the header — treat as no usable
		// reply rather than a hard probe failure.
		return buildFinding(target, "no usable reply", false), nil
	}
	if !wire.IsResponseFrame(buf[:n]) {
		return buildFinding(target, fmt.Sprintf("non-SLMP response (%d bytes)", n), false), nil
	}
	// Read the rest based on the declared length. Cap the read
	// at MaxResponseDataLength so a malicious peer can't trick
	// the probe into a giant alloc.
	declaredLen := int(buf[7]) | int(buf[8])<<8
	if declaredLen > wire.MaxResponseDataLength {
		return buildFinding(target, fmt.Sprintf("absurd SLMP length (%d)", declaredLen), false), nil
	}
	total := wire.HeaderLenResponse + declaredLen
	if total > len(buf) {
		bigger := make([]byte, total)
		copy(bigger, buf[:n])
		buf = bigger
	}
	if _, err := io.ReadFull(conn, buf[n:total]); err != nil {
		return buildFinding(target, fmt.Sprintf("short SLMP body (declared %d)", declaredLen), false), nil
	}
	cpu, perr := wire.ParseReadCPUModelName(buf[:total])
	if perr != nil {
		return buildFinding(target, classifyParseError(perr), false), nil
	}
	note := "SLMP CPU"
	if cpu.Model != "" {
		note = fmt.Sprintf("SLMP model=%s type=0x%04x", sanitizeModel(cpu.Model), cpu.CPUType)
	}
	return buildFinding(target, note, true), nil
}

// REPL stub; the generic REPL framework lands later. Operators who
// want to inspect the parsed CPUInfo can read the finding's note
// (model + CPU type code) until the REPL ships.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("slmp: REPL arrives with the generic framework")
}

// ProxyHandler returns a wire-layer write-ban handler. SLMP is TCP
// so the generic proxy framework applies, but the SLMP write
// services (Batch Write 0x1401, Random Write 0x1402, Remote RUN
// 0x1620, Remote STOP 0x1621, Remote PAUSE 0x1622, Remote LATCH
// CLEAR 0x1624, Remote RESET 0x1625, Clear Error 0x1619) are all
// gate-targets in their own right. The default-build proxy
// rejects every request with an SLMP "command unsupported" end
// code (0xC059) before forwarding, matching the protocol's own
// refusal idiom.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &writeBanHandler{} }

type writeBanHandler struct{}

func (writeBanHandler) Handle(ctx context.Context, client, _ io.ReadWriter) error {
	// Read the first frame's header to learn the declared length;
	// then drain the body and reply with a refusal end code. We
	// do not forward to upstream — defence-in-depth: the
	// classifier could be bypassed by a malformed length, so we
	// fail-closed for every request in the default build.
	hdr := make([]byte, wire.HeaderLenRequest)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return err
	}
	declaredLen := int(hdr[7]) | int(hdr[8])<<8
	if declaredLen > wire.MaxResponseDataLength {
		// Malformed; drop the connection.
		return fmt.Errorf("slmp: oversized request (declared %d)", declaredLen)
	}
	body := make([]byte, declaredLen)
	if _, err := io.ReadFull(client, body); err != nil {
		return err
	}
	// Reply with a 13-byte error frame: subheader 0xD000 +
	// routing echo + declared length 2 (just end code) + end
	// code 0xC059 ("command unsupported" per SLMP §6.6 end-code
	// table). The routing fields echo the request's so older
	// clients that validate them stay happy.
	resp := []byte{
		0xD0, 0x00, // response subheader
		hdr[2],         // network
		hdr[3],         // PC
		hdr[4], hdr[5], // IO
		hdr[6],     // station
		0x02, 0x00, // declared length (2: end code only)
		0x59, 0xC0, // end code 0xC059 (command unsupported)
	}
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
// note phrase the operator can scan.
func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short SLMP frame"
	case errors.Is(err, wire.ErrLengthMismatch):
		return "SLMP length-field mismatch"
	case errors.Is(err, wire.ErrEndCodeNonZero):
		return "SLMP end-code non-zero (CPU refused)"
	case errors.Is(err, wire.ErrNotResponse):
		return "SLMP frame not a response (subheader != 0xD000)"
	default:
		return "SLMP parse failure"
	}
}

// sanitizeModel strips bytes outside the printable-ASCII range so
// a model field cannot smuggle ANSI escapes or control characters
// into the finding hash payload (downstream consumers render the
// note via SafeBytes anyway, but defence-in-depth is cheap).
func sanitizeModel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func buildFinding(target core.Target, note string, isSLMP bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // legacy ICS, no auth on default port
		"exposure":      75,
		"auth_state":    95, // SLMP has no native authentication
		"capability":    30,
		"impact_class":  75, // factory-floor PLCs
		// cve_exposure: 10 (v2.33+, bumped from 6) — Mitsubishi
		// MELSEC + SLMP-speaking GOT HMIs have a wide CVE
		// catalogue across iQ-R, iQ-F, Q-series, FX-series.
		// Anchors:
		//   CVE-2017-14924 (MELSEC Q DoS).
		//   CVE-2018-15745 (FX series unauth-write).
		//   CVE-2019-13555 (iQ-R / iQ-F auth bypass).
		//   CVE-2020-5594 (MELSEC iQ-R OPC UA stack DoS).
		//   CVE-2021-20593 (iQ-R uncontrolled resource consumption).
		//   CVE-2022-26318 (GOT2000 HMI siblings).
		//   CVE-2023-3373 (iQ-F module info disclosure).
		//   CVE-2023-46868 (MELSOFT GX Works3 cred-store).
		//   CVE-2024-21858 (MELSEC iQ-F serial-bridge bypass).
		//   CVE-2025-1432 (SLMP-related undocumented diag service).
		"cve_exposure": 10,
	}
	if isSLMP {
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
