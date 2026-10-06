package melsoft

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
	"local/elsereno/internal/cve"
	"local/elsereno/internal/protocols/melsoft/wire"
	"local/elsereno/internal/scoring"
)

// Name is the plugin identifier.
const Name = "melsoft"

// DefaultPort is the MELSOFT communication port (TCP/IP) of a QnUCPU
// built-in Ethernet port, reserved by the system (Mitsubishi
// SH(NA)-080811ENG, Appendix 2); iQ-R lists the same number (secondary:
// the pymelsec README table). E71 Ethernet modules use TCP/5002 for MELSOFT
// instead (LJ71E71 manual, Appendix 2); probe that port explicitly with
// --target host:5002.
const DefaultPort core.Port = 5007

// Plugin implements core.Protocol over TCP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with sensible timeouts. MELSOFT needs no
// banner or negotiation, so a single round-trip fingerprints.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "MELSOFT (GX Works engineering protocol) read-only fingerprint on TCP/5007, the MELSEC CPU MELSOFT communication port",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends the fixed MELSOFT get-CPU-info
// request, classifies the reply by its 0xD7 response marker, and folds
// the extracted CPU model into the finding hash. No memory-device read
// or write is performed; the default build is read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("melsoft: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildGetCPUInfo()); err != nil {
		return nil, fmt.Errorf("melsoft: write: %w", err)
	}

	// Accumulate until we have enough for a model or the peer goes
	// quiet (the deadline bounds the loop).
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for len(buf) < wire.MinResponseLen {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	if len(buf) == 0 {
		return buildFinding(target, "no usable reply", false, ""), nil
	}
	info, perr := wire.ParseCPUInfo(buf)
	switch {
	case errors.Is(perr, wire.ErrNotResponse):
		return buildFinding(target, fmt.Sprintf("non-MELSOFT response (%d bytes)", len(buf)), false, ""), nil
	case perr != nil:
		return buildFinding(target, classifyParseError(perr), false, ""), nil
	}
	note := "MELSOFT CPU"
	if info.Model != "" {
		note = "MELSOFT model=" + sanitizeModel(info.Model)
	}
	return buildFinding(target, note, true, sanitizeModel(info.Model)), nil
}

// REPL stub; the generic REPL framework lands later.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("melsoft: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. The MELSOFT service
// layer (program read/write, RUN/STOP, parameter transfer) is a
// proprietary TLV stack that is not modelled here; the default-build
// proxy refuses the session rather than relay bytes it cannot gate.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("melsoft: TCP proxy requires a MELSOFT-aware classifier; this build is fingerprint-only")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short MELSOFT reply"
	case errors.Is(err, wire.ErrNotResponse):
		return "MELSOFT marker (0xD7) absent"
	default:
		return "MELSOFT parse failure"
	}
}

// sanitizeModel strips bytes outside printable ASCII so a model field
// cannot smuggle control bytes into the finding hash payload.
func sanitizeModel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func buildFinding(target core.Target, note string, isMELSOFT bool, model string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 80, // legacy ICS, no auth on the direct-connect port
		"exposure":      75,
		"auth_state":    95, // the MELSOFT communication port has no native auth
		"capability":    30,
		"impact_class":  75, // factory-floor PLCs
		// cve_exposure 10: conservative baseline for the Mitsubishi
		// MELSEC family. When the CPU model name prefix names the series,
		// cve.ForSLMP (a MELSEC-model-to-CVE map, protocol-agnostic)
		// raises it with NVD-verified CVEs (iQ-F/FX5: CVE-2025-7731 +
		// CVE-2024-8403; iQ-R: CVE-2020-5668). Classic Q / L / legacy FX
		// get the baseline only.
		"cve_exposure": 10,
	}
	if isMELSOFT {
		factors["capability"] = 75
		if recs := cve.ForSLMP(model); len(recs) > 0 {
			if s := cve.Score(recs); s > factors["cve_exposure"] {
				factors["cve_exposure"] = s
			}
			note += " cve=" + strings.Join(cve.IDs(recs), ",")
		}
	}
	score := scoring.ScoreDefault(factors)
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
