package iec104

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/iec104/wire"
)

// Name is the plugin identifier.
const Name = "iec104"

// DefaultPort is the well-known port.
const DefaultPort core.Port = 2404

// Plugin implements core.Protocol.
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
		Description: "IEC 60870-5-104 (power SCADA) TESTFR fingerprint on port 2404",
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
		return nil, fmt.Errorf("iec104: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))
	if _, err := conn.Write(wire.BuildTESTFR()); err != nil {
		return nil, fmt.Errorf("iec104: write: %w", err)
	}
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	apci, perr := wire.ParseAPCI(buf[:n])
	isOK := perr == nil && (apci.Type() == wire.FrameU || apci.Type() == wire.FrameS)
	note := "silent"
	if isOK {
		note = fmt.Sprintf("IEC-104 %s-frame", apci.Type())
	}
	return buildFinding(target, note, isOK), nil
}

// REPL stub until the generic REPL framework lands.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("iec104: REPL arrives with the generic framework")
}

// ProxyHandler returns the default IEC-104 proxy, which refuses
// I-format APDUs (the only frame type carrying ASDUs, including
// Control-family commands that can mutate grid state) by replying
// with a STOPDT_act U-frame (ADR-040). S-format and U-format frames
// forward untouched so the data-transfer lifecycle completes. The
// offensive build substitutes an ASDU-aware handler that routes
// Control ASDUs through the triple-confirm wrapper.
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

// forwardFiltered reads one APDU at a time. Non-I frames forward;
// I frames are short-circuited with a STOPDT_act refusal.
func forwardFiltered(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	apci := make([]byte, wire.APCILen)
	for {
		if _, err := io.ReadFull(client, apci); err != nil {
			return err
		}
		a, err := wire.ParseAPCI(apci)
		if err != nil {
			return err
		}
		// APDU total = 2 start+length bytes + Length. The 4 control
		// bytes are part of Length, so payload size = Length - 4.
		payloadLen := int(a.Length) - 4
		payload := make([]byte, payloadLen)
		if payloadLen > 0 {
			if _, err := io.ReadFull(client, payload); err != nil {
				return err
			}
		}
		if wire.Classify(a) == wire.CategoryRead {
			if _, werr := upstream.Write(apci); werr != nil {
				return werr
			}
			if payloadLen > 0 {
				if _, werr := upstream.Write(payload); werr != nil {
					return werr
				}
			}
			continue
		}
		if _, werr := clientWriter.Write(wire.BuildRefusal()); werr != nil {
			return werr
		}
	}
}

func buildFinding(target core.Target, note string, isOK bool) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 90,
		"exposure":      80,
		"auth_state":    85,
		"capability":    30,
		"impact_class":  90,
		// cve_exposure 10: CVE-2015-7906 (Siemens SIPROTEC IEC
		// 104 stack), CVE-2017-12089 (Siemens SICAM PAS), CVE-
		// 2019-13548 (Siemens SICAM PAS) — well-documented
		// substation-automation family. impact_class is already
		// 90 so the additional cve_exposure pushes scoring into
		// the highest severity bucket on positive ID.
		"cve_exposure": 10,
	}
	if isOK {
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
