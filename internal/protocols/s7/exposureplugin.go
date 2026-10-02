package s7

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scoring"
)

// ExposureName is the opt-in exposure plugin's identifier. It is a
// separate plugin from the s7 fingerprint (which only does COTP CR/CC):
// this one drives the full posture read (Setup + SZL protection +
// identity) and scores the result. DefaultPort 0 keeps it OUT of the
// default scan/discover sweep, so it runs only when explicitly named:
//
//	elsereno fingerprint probe --plugin s7-exposure --target plc:102
const ExposureName = "s7-exposure"

// ExposurePlugin implements core.Protocol for the opt-in S7 CPU exposure
// probe. It reuses ProbePosture, so its wire is validated byte for byte
// against a real capture (see the s7 wire tests). Read-only.
type ExposurePlugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// DefaultExposure returns an ExposurePlugin with conservative timeouts.
func DefaultExposure() *ExposurePlugin {
	return &ExposurePlugin{DialTimeout: 5 * time.Second, IOTimeout: 5 * time.Second}
}

// Metadata implements core.Protocol. DefaultPort 0 marks it opt-in: the
// discover/scan sweep skips DefaultPort==0 plugins, so this never probes
// a target unless the operator names it with --plugin.
func (p *ExposurePlugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        ExposureName,
		Description: "S7 CPU exposure probe (opt-in, read-only): protection level + identity via SZL; not in default scans",
		DefaultPort: 0,
		Build:       "default",
		Version:     "v1",
		OptIn:       true,
	}
}

// Probe drives the full S7 posture read and scores it. A CPU that accepts
// writes/control without a password (effective protection level 0/1) scores
// as a high-severity exposure; a password-protected CPU scores lower.
func (p *ExposurePlugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("s7-exposure: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	res, err := ProbePosture(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("s7-exposure: probe %s: %w", addr, err)
	}
	return buildExposureFinding(target, res), nil
}

// REPL implements core.Protocol; the exposure probe has no interactive mode.
func (p *ExposurePlugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("s7-exposure: no REPL (probe-only)")
}

// ProxyHandler implements core.Protocol; the exposure probe is not proxied.
func (p *ExposurePlugin) ProxyHandler() core.ProxyHandler { return exposureNoProxy{} }

type exposureNoProxy struct{}

func (exposureNoProxy) Handle(_ context.Context, _, _ io.ReadWriter) error {
	return fmt.Errorf("s7-exposure: probe-only plugin is not proxied")
}

// buildExposureFinding scores the posture result. The four state-dependent
// factors (exposure, auth_state, capability, and the note that keys the
// finding hash) move with what the probe actually learned; the three
// invariant S7 factors match the s7 fingerprint plugin.
func buildExposureFinding(target core.Target, res PostureResult) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85,
		"impact_class":  80, // S7 PLCs drive safety-adjacent processes
		"cve_exposure":  14, // same S7 CVE surface as the s7 fingerprint
	}
	var note string
	switch {
	case !res.IsS7:
		factors["exposure"] = 20
		factors["auth_state"] = 50
		factors["capability"] = 10
		note = "not-s7"
	case !res.ProtectionRead:
		// S7 confirmed but the protection SZL was refused/unreadable: a
		// sign of a locked-down CPU, but unconfirmed either way.
		factors["exposure"] = 60
		factors["auth_state"] = 60
		factors["capability"] = 50
		note = "protection-unreadable " + res.OrderNumber
	case res.Exposed:
		// The exposure: writable/controllable without a password.
		factors["exposure"] = 95
		factors["auth_state"] = 95
		factors["capability"] = 80
		note = fmt.Sprintf("EXPOSED real=%d mode=%d %s/%s",
			res.Protection.RealLevel, res.Protection.ModeSelector, res.OrderNumber, res.Firmware)
	default:
		// Protection enforced (effective level 2/3): a password is required.
		factors["exposure"] = 55
		factors["auth_state"] = 35
		factors["capability"] = 70
		note = fmt.Sprintf("protected real=%d %s/%s",
			res.Protection.RealLevel, res.OrderNumber, res.Firmware)
	}
	score := scoring.ScoreDefault(factors)
	return &core.Finding{
		ID:          hashID(target, note),
		Protocol:    ExposureName,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, note),
	}
}
