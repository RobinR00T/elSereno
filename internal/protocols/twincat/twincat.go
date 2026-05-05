// Package twincat implements the read-only fingerprint
// for Beckhoff TwinCAT ADS over TCP/48898. v1.54 chunk 1.
//
// TwinCAT is the Beckhoff PC-based control suite that
// runs on Beckhoff IPCs (CXxxxx, IPCxxxx series) +
// embedded controllers + bus terminals (BC9xxx). The
// runtime listens on TCP/48898 by default for the AMS
// Router; engineering tools (TwinCAT XAE, TwinCAT 3
// IDE) connect there.
//
// We send a Read Device Info request to AMS port 10000
// (the AMS Router's well-known port) with an all-zero
// target NetID. Most runtimes answer regardless of NetID
// for this read-only command; the response includes the
// runtime name (e.g. "TCatRouter", "TC3 PLC1") + version
// triple (major.minor.build, e.g. 3.1.4024 for TC3 build
// 4024).
//
// The probe is read-only by design.
package twincat

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
	"local/elsereno/internal/protocols/twincat/wire"
)

// Name is the plugin identifier.
const Name = "twincat"

// DefaultPort is the canonical TwinCAT ADS port.
const DefaultPort core.Port = 48898

// Plugin implements core.Protocol over TCP.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
	// TargetNetID is the operator-supplied AMS Net ID
	// to put in the request header. Empty (zero-value)
	// means "all-zero NetID"; many runtimes answer
	// anyway. Operators with prior knowledge of the
	// device's NetID override.
	TargetNetID [6]byte
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        Name,
		Description: "Beckhoff TwinCAT ADS read-only fingerprint on TCP/48898 (CXxxxx IPCs, embedded PCs, BC bus terminals — TC2 + TC3 runtimes).",
		DefaultPort: DefaultPort,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe implements core.Protocol. Sends a ReadDeviceInfo
// request and parses the response into a finding note
// with name + version (e.g. "TwinCAT TCatRouter
// 3.1.4024"). On any AMS-level failure the finding is
// negative with the parser's classification.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("twincat: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildReadDeviceInfo(p.TargetNetID)); err != nil {
		return nil, fmt.Errorf("twincat: write: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return buildFinding(target, "no usable reply", false), nil
	}
	info, perr := wire.ParseDeviceInfo(buf[:n])
	if perr != nil {
		return buildFinding(target, classifyParseError(perr), false), nil
	}
	note := fmt.Sprintf("TwinCAT %s %d.%d.%d", info.Name, info.MajorVersion, info.MinorVersion, info.VersionBuild)
	return buildFinding(target, note, true), nil
}

// REPL stub.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("twincat: REPL arrives with the generic framework")
}

// ProxyHandler returns a fail-closed handler. ADS write
// services exist (Write, WriteControl, AddDeviceNotification)
// but are out of scope for v1.54; the default-build proxy
// refuses the session immediately. A dedicated relay
// arrives with the future offensive plugin.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

type failClosed struct{}

func (failClosed) Handle(_ context.Context, _ io.ReadWriter, _ io.ReadWriter) error {
	return fmt.Errorf("twincat: TCP proxy framework requires a TwinCAT-aware classifier; v1.54 is fingerprint-only — a relay arrives with the future offensive plugin")
}

func classifyParseError(err error) string {
	switch {
	case errors.Is(err, wire.ErrShortFrame):
		return "short AMS reply"
	case errors.Is(err, wire.ErrBadAMSTCP):
		return "non-AMS reply on port 48898"
	case errors.Is(err, wire.ErrLengthMismatch):
		return "AMS length mismatch"
	case errors.Is(err, wire.ErrNotADSResponse):
		return "AMS reply was not a ReadDeviceInfo response"
	default:
		return "AMS classify failure"
	}
}

func buildFinding(target core.Target, note string, isTwinCAT bool) *core.Finding {
	factors := map[string]int{
		// TwinCAT runs on Beckhoff PC-class controllers + EtherCAT
		// couplers; typical industrial-floor blast radius.
		"protocol_risk": 80,
		"exposure":      70,
		"auth_state":    85, // TC3 supports authentication but many fielded systems run open
		"capability":    30,
		"impact_class":  75,
		"cve_exposure":  10, // CVE-2020-12525, CVE-2022-23166, CVE-2023-37452 etc.
	}
	if isTwinCAT {
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
