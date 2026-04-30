package mms

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
	"local/elsereno/internal/protocols/mms/wire"
)

// Name is the plugin identifier.
const Name = "mms"

// DefaultPort is the canonical IEC 61850 MMS port (shared with
// S7). The plugin's COTP-CR uses MMS-specific TSAPs to
// disambiguate from S7 responses.
const DefaultPort core.Port = 102

// Plugin implements core.Protocol over TCP.
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
		Description: "IEC 61850 MMS read-only fingerprint on TCP/102 (substation protection relays, RTUs, merging units; disambiguates from S7 via MMS TSAPs)",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends TPKT + COTP-CR with
// MMS-style TSAPs (`00 01` source and destination) and
// classifies the response:
//
//   - COTP-CC → MMS-compatible server (positive).
//   - COTP-DR → likely S7 or other non-MMS server on port 102.
//   - non-TPKT → not OSI on port 102.
//
// No service-request frames are issued — the default build is
// read-only by design.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("mms: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if err := wire.WriteTPKT(conn, wire.BuildCOTPConnectionRequestMMS()); err != nil {
		return nil, fmt.Errorf("mms: write CR: %w", err)
	}

	tpkt, err := wire.ReadTPKT(conn)
	if err != nil {
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return buildFinding(target, "silent close", false), nil
		case errors.Is(err, wire.ErrBadTPKT):
			return buildFinding(target, "non-TPKT reply on port 102", false), nil
		default:
			return nil, fmt.Errorf("mms: read TPKT: %w", err)
		}
	}

	note, cerr := wire.ClassifyCOTP(tpkt.Payload)
	if cerr != nil {
		return buildFinding(target, classifyParseError(cerr), false), nil
	}
	return buildFinding(target, "MMS "+note, true), nil
}

// REPL stub — consistent with every other protocol plugin.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("mms: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. MMS's deeper
// service-request layer (ACSE association + Read /
// GetVariableAccessAttributes / etc.) is not implemented in
// v1.25; the default-build proxy refuses the session
// immediately rather than relay opaque OSI bytes. A dedicated
// relay arrives with the future offensive plugin.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("mms: TCP proxy framework requires an MMS-aware classifier; v1.25 is fingerprint-only — a relay arrives with the future offensive plugin")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortCOTP):
		return "short MMS COTP reply"
	case errors.Is(err, wire.ErrNotCOTPConfirm):
		return "MMS COTP got DR (likely S7 or non-MMS server)"
	default:
		return "MMS classify failure"
	}
}

func buildFinding(target core.Target, note string, isMMS bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85, // substation protection / circuit-breaker control
		"exposure":      75,
		"auth_state":    85, // IEC 61850-8-1 supports ACSE auth but many deployments don't enforce
		"capability":    30,
		"impact_class":  85, // grid-scale blast radius (transmission + distribution)
		// cve_exposure: 9 — IEC 61850 MMS family has a recurring
		// CVE record across vendors. Anchor CVEs:
		//   CVE-2018-13802 (Siemens SIPROTEC 4 / DIGSI 4 OSI stack DoS).
		//   CVE-2020-7517  (Schneider EcoStruxure Power Operation MMS).
		//   CVE-2021-22779 (Schneider IEC 61850 auth bypass).
		//   CVE-2022-3008  (libIEC61850 stack RCE multi-vendor).
		//   CVE-2023-39435 (SEL-3530 RTAC MMS write-without-auth).
		"cve_exposure": 9,
	}
	if isMMS {
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
