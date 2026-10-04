package codesys

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/codesys/wire"
)

// ActiveName is the opt-in active-probe plugin identifier.
const ActiveName = "codesys-active"

// ActivePlugin is an OPT-IN CoDeSys fingerprint that sends the
// host-independent channel-open PDU (wire.BuildChannelOpen, ported byte
// for byte from the Tenable reference) so a gateway can be confirmed by
// its Block-Driver-framed reply, not just by a plaintext banner. It is a
// read-only detection handshake: it opens a channel to read the reply
// and issues no state-reading or state-changing service request.
//
// It is kept out of the default read-only sweep (DefaultPort 0, OptIn):
// the default `codesys` plugin stays banner + magic-recognition only, so
// a normal scan never opens a gateway channel. Run it explicitly:
//
//	elsereno fingerprint probe --plugin codesys-active --target plc:1217
//
// The channel-open frame is validated byte for byte against the Tenable
// PoC (wire/channel_test.go) but has NOT been exercised against a live
// 1217 gateway, so the reply is classified by the capture-confirmed
// Block Driver magic (wire.Classify) rather than a presumed reply shape.
type ActivePlugin struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// DefaultActive returns an ActivePlugin with sensible timeouts.
func DefaultActive() *ActivePlugin {
	return &ActivePlugin{DialTimeout: 5 * time.Second, IOTimeout: 3 * time.Second}
}

// Metadata implements core.Protocol. DefaultPort 0 + OptIn keep it out
// of the discover/scan sweep; it runs only when named with --plugin.
func (p *ActivePlugin) Metadata() core.PluginMetadata {
	return core.PluginMetadata{
		Name:        ActiveName,
		Description: "CoDeSys V3 opt-in active fingerprint: sends the channel-open PDU and confirms by the Block-Driver reply (read-only detection; run with --plugin codesys-active --target host:1217)",
		DefaultPort: 0,
		Build:       "default",
		Version:     "v1",
		OptIn:       true,
	}
}

// Probe implements core.Protocol. It sends the channel-open PDU with a
// random client-chosen channel id and classifies the reply via the
// Block Driver magic (or a banner substring, as a fallback). No service
// request is issued.
func (p *ActivePlugin) Probe(ctx context.Context, target core.Target) (*core.Finding, error) {
	addr := net.JoinHostPort(target.Address.String(), fmt.Sprintf("%d", target.Port))
	d := net.Dialer{Timeout: p.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("codesys-active: dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(p.IOTimeout))

	if _, err := conn.Write(wire.BuildChannelOpen(randomChannelID())); err != nil {
		return nil, fmt.Errorf("codesys-active: write: %w", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return buildFinding(target, "channel-open got no usable reply", false), nil
	}
	note, cerr := wire.Classify(buf[:n])
	if cerr != nil {
		return buildFinding(target, "channel-open "+classifyParseError(cerr), false), nil
	}
	return buildFinding(target, "CoDeSys channel-open "+note, true), nil
}

// REPL stub.
func (p *ActivePlugin) REPL(_ context.Context, _ *core.Session) error {
	return fmt.Errorf("codesys-active: probe-only plugin has no REPL")
}

// ProxyHandler returns the same fail-closed handler as the default
// plugin; the opt-in probe is not a proxy.
func (p *ActivePlugin) ProxyHandler() core.ProxyHandler { return &failClosed{} }

// randomChannelID returns a non-zero client-chosen channel id. A gateway
// treats it as an opaque nonce; crypto/rand avoids a predictable id
// without implying any security property.
func randomChannelID() uint32 {
	var b [4]byte
	for i := 0; i < 4; i++ {
		if _, err := cryptorand.Read(b[:]); err != nil {
			return 1
		}
		if id := binary.LittleEndian.Uint32(b[:]); id != 0 {
			return id
		}
	}
	return 1
}
