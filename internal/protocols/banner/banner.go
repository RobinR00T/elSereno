// Package banner is the default "fingerprint by raw TCP banner"
// plugin. It opens a connection, reads up to MaxBannerBytes, and emits
// a Finding whose payload carries the sanitised banner (via
// internal/render.SafeBytes).
//
// Banner is registered in default builds because it is read-only and
// useful against any TCP port. Protocol-specific plugins in F2+ take
// precedence when they match.
package banner

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
	"local/elsereno/internal/render"
)

// MaxBannerBytes caps how much of the initial banner we read. Matches
// evidence.max_payload_bytes default in the brief.
const MaxBannerBytes = 16384

// Plugin opens a TCP connection and reads a banner. Implements
// core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	ReadTimeout time.Duration
}

// Default returns a Plugin with sensible timeouts.
func Default() *Plugin {
	return &Plugin{
		DialTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second,
	}
}

// Metadata implements core.Protocol.
func (p *Plugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        "banner",
		Description: "Raw TCP banner fingerprint (read-only, safe default)",
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
		return nil, fmt.Errorf("banner: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(p.ReadTimeout))
	buf := make([]byte, MaxBannerBytes)
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		// Timeouts on banner-passive services are normal; we still
		// emit a Finding with an empty banner so the target is
		// recorded.
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return nil, fmt.Errorf("banner: read %s: %w", addr, err)
		}
	}
	raw := buf[:n]
	_ = render.SafeBytes(raw) // sanitised payload is captured by the evidence writer in F2
	sum := sha256.Sum256(raw)

	factors := map[string]int{
		"protocol_risk": 5, // low — banner is read-only.
		"exposure":      50,
		"auth_state":    50,
		"capability":    10,
		"impact_class":  10,
		"cve_exposure":  0,
	}
	score := 5 + 10 + 10 + 2 + 1 + 0 // ≈ 28 in the "low" band.

	return &core.Finding{
		ID:          core.UUID(hex.EncodeToString(sum[:16])),
		Protocol:    "banner",
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: sum[:],
	}, nil
}

// REPL is not meaningful for banner; returning an error documents
// that.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("banner: no REPL; use `elsereno scan` or a protocol-specific plugin")
}

// ProxyHandler returns nil — banner has no proxy mode.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return nil }

// Evidence captures the sanitised banner for attaching to the finding.
// Callers hand it to the evidence writer along with the finding.
func Evidence(rawBanner []byte) (sanitised string, hash []byte) {
	h := sha256.Sum256(rawBanner)
	return render.SafeBytes(rawBanner), h[:]
}
