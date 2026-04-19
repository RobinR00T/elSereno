package atmodem

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/atmodem/wire"
	"local/elsereno/internal/render"
)

// Name is the plugin identifier.
const Name = "atmodem"

// CandidatePorts is the set of TCP ports the brief lists as common
// AT-over-TCP exposures. Only used as a hint; the scanner targets
// whatever ports are on the input list.
var CandidatePorts = []core.Port{
	7, 23, 3001, 9999,
	2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
	2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020,
	2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030,
	2031, 2032,
	4001, 4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009,
	10001, 10002, 10003, 10004,
}

// Plugin implements core.Protocol.
type Plugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// Default returns a Plugin with conservative timeouts (AT modems
// often answer within a second; we wait five for slow serial bridges).
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
		Description: "AT modem (Hayes / GSM / EN 81-28) read-only probe + fingerprint",
		DefaultPort: 9999,
		Build:       "default",
		Version:     "v1",
	}
}

// Probe drives a short fingerprinting conversation. It sends:
//
//	AT         — any AT-speaker answers OK/ERROR.
//	ATI        — Hayes-style identify (banner).
//	AT+CGMI    — GSM extended identify (manufacturer).
//
// Classification lives in wire.Detect.
func (p *Plugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("atmodem: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	// Drain any unsolicited banner the device might emit before we
	// speak. 100 ms window is generous without stalling the scanner.
	initial := drainBanner(conn, 100*time.Millisecond)

	ok, err := sendAndExpectOK(conn, "AT")
	if err != nil {
		return nil, fmt.Errorf("atmodem: AT: %w", err)
	}
	if !ok {
		// Not an AT speaker; emit an info-level finding.
		return infoFinding(target, "AT did not elicit OK", initial), nil
	}

	atiBody, _ := sendAndCollect(conn, "ATI")
	cgmiBody, _ := sendAndCollect(conn, "AT+CGMI")

	fp := wire.Detect(initial+"\n"+atiBody, cgmiBody)
	return buildFinding(target, fp, initial, atiBody, cgmiBody), nil
}

// REPL hookup lands with the generic REPL in F4. The default-build
// REPL refuses dial / SMS / write commands; the allow-list lives
// next to ForbiddenPrefixes.
func (p *Plugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("atmodem: REPL binding arrives with the generic REPL hookup in F4")
}

// ProxyHandler returns the AT proxy handler that inspects each line
// the client writes upstream and blocks the destructive set.
func (p *Plugin) ProxyHandler() core.ProxyHandler { return &proxy{} }

// ForbiddenPrefixes are the command prefixes the proxy refuses in
// read-only mode (brief section 7 F2b, conventions.md).
var ForbiddenPrefixes = []string{
	"ATD",        // dial any
	"ATA",        // answer
	"AT+CMGS",    // send SMS
	"AT+CMGW",    // write SMS
	"AT+CMSS",    // send stored SMS
	"AT+CMGD",    // delete SMS
	"AT+CFUN",    // radio on/off
	"AT+CPWROFF", // power off
	"+++",        // escape-to-command sequence
}

// IsForbiddenCommand returns true if line starts with any of
// ForbiddenPrefixes. Matching is case-insensitive and tolerates
// leading whitespace.
func IsForbiddenCommand(line string) bool {
	trimmed := strings.ToUpper(strings.TrimSpace(line))
	if trimmed == "" {
		return false
	}
	for _, p := range ForbiddenPrefixes {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// proxy implements core.ProxyHandler with per-line inspection.
type proxy struct{}

// Handle forwards client -> upstream lines after IsForbiddenCommand
// veto, and upstream -> client bytes unmodified.
func (h *proxy) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	errs := make(chan error, 2)

	// client -> upstream: line-by-line veto.
	go func() {
		errs <- forwardAndFilter(client, upstream)
	}()
	// upstream -> client: bytes unmodified, but rendered via SafeBytes
	// by the log writer (F3 will wire the log sink; here we forward).
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

func forwardAndFilter(client io.Reader, upstream io.Writer) error {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := client.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := indexOfLineEnd(buf)
				if idx < 0 {
					break
				}
				line := string(buf[:idx])
				buf = buf[idx+1:]
				if IsForbiddenCommand(line) {
					// Swallow the line and reply ERROR.
					if _, werr := upstream.Write([]byte("")); werr != nil {
						return werr
					}
					continue
				}
				if _, werr := upstream.Write([]byte(line + "\r")); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			return err
		}
	}
}

func indexOfLineEnd(b []byte) int {
	for i, c := range b {
		if c == '\r' || c == '\n' {
			return i
		}
	}
	return -1
}

// sendAndExpectOK writes cmd + CR and returns true if the response is
// ResultOK.
func sendAndExpectOK(conn net.Conn, cmd string) (bool, error) {
	if _, err := conn.Write([]byte(cmd + "\r")); err != nil {
		return false, err
	}
	r, err := wire.ReadResponse(conn)
	if err != nil {
		return false, err
	}
	return r.Result == wire.ResultOK, nil
}

// sendAndCollect writes cmd + CR and returns the concatenated body
// lines (excluding the terminal code). An ERROR response returns "".
func sendAndCollect(conn net.Conn, cmd string) (string, error) {
	if _, err := conn.Write([]byte(cmd + "\r")); err != nil {
		return "", err
	}
	r, err := wire.ReadResponse(conn)
	if err != nil {
		return "", err
	}
	return strings.Join(r.Lines, "\n"), nil
}

// drainBanner reads up to 2 KiB for a short window to capture
// unsolicited banner text emitted on connect.
func drainBanner(conn net.Conn, window time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(window))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	// Reset deadline for subsequent reads.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	return render.SafeBytes(buf[:n])
}

// buildFinding assembles the scored Finding from the fingerprint.
func buildFinding(target core.Target, fp wire.Fingerprint, initial, ati, cgmi string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 60,
		"exposure":      70,
		"auth_state":    80,
		"capability":    30,
		"impact_class":  40,
		"cve_exposure":  0,
	}
	switch fp.Class {
	case wire.ClassGSM:
		factors["protocol_risk"] = 75
		factors["impact_class"] = 60 // SMS/IMSI capture risk
	case wire.ClassLift:
		factors["protocol_risk"] = 85
		factors["impact_class"] = 90 // EN 81-28: lift alarm path
	case wire.ClassHayes, wire.ClassUnknown:
		// keep defaults
	}
	score := scoreFor(factors)
	note := fmt.Sprintf("class=%s vendor=%s", fp.Class, fp.Vendor)
	return &core.Finding{
		ID:          hashID(target, note),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, note, initial, ati, cgmi),
	}
}

// infoFinding is used when AT doesn't elicit OK (the port speaks
// something else or is silent).
func infoFinding(target core.Target, note, initial string) *core.Finding {
	factors := map[string]int{
		"protocol_risk": 10,
		"exposure":      40,
		"auth_state":    50,
		"capability":    5,
		"impact_class":  5,
		"cve_exposure":  0,
	}
	score := scoreFor(factors)
	return &core.Finding{
		ID:          hashID(target, note),
		Protocol:    Name,
		Severity:    core.SeverityFromScore(score),
		Score:       score,
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		Factors:     factors,
		FindingHash: hashBytes(target, note, initial),
	}
}

func scoreFor(factors map[string]int) int {
	weights := map[string]float64{
		"protocol_risk": 0.25,
		"exposure":      0.20,
		"auth_state":    0.20,
		"capability":    0.15,
		"impact_class":  0.10,
		"cve_exposure":  0.10,
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

// portBytes splits a uint16 port into two bytes (hi, lo) so hashes
// include the port without passing an int through byte() and
// tripping G115.
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

func hashBytes(target core.Target, parts ...string) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(target.Address.String()))
	pb := portBytes(target.Port)
	_, _ = h.Write(pb[:])
	for _, s := range parts {
		_, _ = h.Write([]byte(s))
	}
	return h.Sum(nil)
}
