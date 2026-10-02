package opcua

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scoring"
)

// ExposureName is the opt-in OPC UA exposure plugin's identifier. It is a
// separate plugin from the opcua fingerprint (which only confirms UA-TCP):
// this one drives the anonymous-access handshake and, if a session opens,
// the bounded writeable-tag walk, then scores the result. DefaultPort 0
// keeps it OUT of the default scan/discover sweep, so it runs only when
// explicitly named:
//
//	elsereno fingerprint probe --plugin opcua-exposure --target plc:4840
const ExposureName = "opcua-exposure"

// defaultExposureMaxNodes bounds the writeable-tag walk so a large or
// hostile address space cannot run away. Matches the `opcua probe-write`
// command default.
const defaultExposureMaxNodes = 500

// ExposurePlugin implements core.Protocol for the opt-in OPC UA exposure
// probe. It reuses ProbeWriteableNodes (which embeds ProbeAnonymousAccess),
// so it is strictly read-only: it opens an anonymous session and reads node
// attributes, it never issues a Write. DefaultPort 0 marks it opt-in.
type ExposurePlugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	MaxNodes    int
}

// DefaultExposure returns an ExposurePlugin with conservative timeouts and
// the default node budget.
func DefaultExposure() *ExposurePlugin {
	return &ExposurePlugin{
		DialTimeout: 5 * time.Second,
		IOTimeout:   15 * time.Second,
		MaxNodes:    defaultExposureMaxNodes,
	}
}

// Metadata implements core.Protocol. DefaultPort 0 marks it opt-in: the
// discover/scan sweep skips DefaultPort==0 plugins, so this never probes a
// target unless the operator names it with --plugin.
func (p *ExposurePlugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        ExposureName,
		Description: "OPC UA exposure probe (opt-in, read-only): anonymous session + writeable-tag walk; not in default scans",
		DefaultPort: 0,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe opens an anonymous OPC UA session and, if it opens, walks the
// address space for anonymous-writeable tags, then scores the result. An
// anonymous session that opens is a high-severity exposure; one that also
// exposes writeable tags is critical; a server that rejects the anonymous
// session (auth enforced) scores lower.
func (p *ExposurePlugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("opcua-exposure: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	maxNodes := p.MaxNodes
	if maxNodes <= 0 {
		maxNodes = defaultExposureMaxNodes
	}
	endpoint := fmt.Sprintf("opc.tcp://%s", addr)
	res, err := ProbeWriteableNodes(ctx, conn, endpoint, maxNodes)
	if err != nil {
		return nil, fmt.Errorf("opcua-exposure: probe %s: %w", addr, err)
	}
	return buildExposureFinding(target, res), nil
}

// REPL implements core.Protocol; the exposure probe has no interactive mode.
func (p *ExposurePlugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("opcua-exposure: no REPL (probe-only)")
}

// ProxyHandler implements core.Protocol; the exposure probe is not proxied.
func (p *ExposurePlugin) ProxyHandler() core.ProxyHandler { return exposureNoProxy{} }

type exposureNoProxy struct{}

func (exposureNoProxy) Handle(_ context.Context, _, _ io.ReadWriter) error {
	return fmt.Errorf("opcua-exposure: probe-only plugin is not proxied")
}

// buildExposureFinding scores the writeable-walk result. The three state-
// dependent factors (exposure, auth_state, capability) and the note that
// keys the finding hash move with what the probe actually learned; the
// three invariant factors match the opcua fingerprint plugin.
func buildExposureFinding(target core.Target, res WriteableWalkResult) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 85, // ICS middleware, widely deployed
		"impact_class":  85, // PLC control plane
		"cve_exposure":  8,  // same OPC UA CVE surface as the opcua fingerprint
	}
	var note string
	switch {
	case !res.IsOPCUA:
		factors["exposure"] = 20
		factors["auth_state"] = 50
		factors["capability"] = 10
		note = "not-opcua"
	case !res.SessionOpened:
		// OPC UA confirmed but the anonymous session was rejected: auth is
		// enforced. The reachable control-plane service is still a finding.
		factors["exposure"] = 50
		factors["auth_state"] = 30
		factors["capability"] = 50
		note = "anon-blocked"
	case len(res.Writeable) > 0:
		// The exposure: a stranger can write control-plane tags.
		factors["exposure"] = 95
		factors["auth_state"] = 95
		factors["capability"] = 85
		note = fmt.Sprintf("EXPOSED writeable=%d walked=%d truncated=%t",
			len(res.Writeable), res.VariablesRead, res.Truncated)
	default:
		// Anonymous session opens (unauthenticated access to the control
		// plane) but no writeable tag was found in the walked subtree.
		factors["exposure"] = 85
		factors["auth_state"] = 90
		factors["capability"] = 45
		note = fmt.Sprintf("anon-open writeable=0 walked=%d truncated=%t",
			res.VariablesRead, res.Truncated)
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
