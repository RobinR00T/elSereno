//go:build offensive

// Package codesys implements the offensive write-gate proxy for the
// CODESYS v3 protocol (TCP/1217 and TCP/11740). CODESYS is the runtime
// behind thousands of PLC/IPC brands (WAGO, Beckhoff, Schneider, IFM,
// Bosch, Festo, ...); an application Download, WriteVars, Start/Stop,
// Reset, or SetOperatingMode changes control logic or run state on a
// live controller.
//
// Framing choice (and why it differs from the FINS/SLMP/GE-SRTP
// handlers). CODESYS v3 has no transport-layer length delimiter a gate
// can trust: the reference Wireshark dissector (fridgebuyer/
// codesys3-dissector) locates L3, L4 and L7 by scanning for byte
// magics, not by reading lengths. Parsing L3/L4 ourselves would mean a
// length we might misread — a classifier bypass. So this handler does
// NOT parse the transport. It buffers the reassembled client->server
// stream and, via internal/protocols/codesys/wire.ScanL7, locates
// EVERY L7 service header (protocol_id magic 0x55cd / 0x7557) and
// classifies each (service_id, cmd_id). A stream is forwarded only
// while every located command is a read or an explicitly allowlisted
// write; any unknown command, non-allowlisted write, or truncated L7
// header at EOF refuses the session (fail-closed: the connection is
// dropped). This is deliberately conservative — it can refuse an
// exotic-but-benign frame — but it cannot be desynchronised into
// forwarding a hidden write: a real write header must carry the magic
// to be parsed by the PLC, so it is always located and classified.
package codesys

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"

	"local/elsereno/internal/protocols/codesys/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedCommand scopes one mutating CODESYS L7 command the operator
// has authorised to forward, by service id + command id. Read commands
// (handshake, status, variable reads) always pass and need no entry;
// entries here open specific writes (e.g. Start, Stop) that would
// otherwise be refused.
type AllowedCommand struct {
	Service byte
	Cmd     byte
}

// command is the wire.Command for an AllowedCommand.
func (a AllowedCommand) command() wire.Command { return wire.MakeCommand(a.Service, a.Cmd) }

// AllowlistHash returns the deterministic SHA-256 over target + the
// sorted allowlist so the operator's dry-run token is stable
// regardless of order.
func AllowlistHash(target string, allowed []AllowedCommand) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Service != sorted[j].Service {
			return sorted[i].Service < sorted[j].Service
		}
		return sorted[i].Cmd < sorted[j].Cmd
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.Service, a.Cmd})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation for the
// CODESYS proxy allowlist.
func SessionMutation(target string, allowed []AllowedCommand) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "codesys",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// CODESYS fail-closed TCP proxy.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional record-replay hook. Nil = no recording.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session through the ADR-039 triple
// confirm. It must be called (and succeed) before Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutation(h.Target, h.Allowed)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise has not
// been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("codesys: write-gated proxy requires Authorise() first")

// ErrRefused ends the session when the client stream contains a
// non-allowlisted command (or a truncated L7 header at EOF). CODESYS
// has no clean per-request refusal frame, so the gate drops the
// connection (fail-closed).
var ErrRefused = errors.New("codesys: stream refused by write-gate")

// maxBuffer caps the client->server reassembly buffer. A control
// session never legitimately holds this much un-forwardable data; a
// stream that grows past it (magic never completing) is refused rather
// than buffered without bound.
const maxBuffer = 1 << 20 // 1 MiB

// Handle implements core.ProxyHandler. Client->upstream is gated by a
// buffered L7 scan; upstream->client responses are a straight copy.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	cw := client
	uw := upstream
	if h.Recorder != nil {
		cw = h.Recorder.WrapClient(cw)
		uw = h.Recorder.WrapUpstream(uw)
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(cw, uw) }()
	go func() {
		_, err := io.Copy(cw, uw)
		errs <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// forward buffers the client->upstream byte stream, locates every L7
// command via wire.ScanL7, refuses on any non-permitted command, and
// forwards validated bytes up to the scan's safeLen (holding back any
// trailing partial header until more data arrives).
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer) error {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	forwarded := 0
	for {
		n, rerr := client.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > maxBuffer {
				return ErrRefused
			}
			cmds, safeLen := wire.ScanL7(buf)
			if !h.streamPermitted(cmds) {
				return ErrRefused
			}
			if safeLen > forwarded {
				if _, werr := upstream.Write(buf[forwarded:safeLen]); werr != nil {
					return werr
				}
				forwarded = safeLen
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				// A magic that never completed before EOF is a
				// truncated command: refuse rather than forward it.
				if wire.HasPartialL7Magic(buf, forwarded) {
					return ErrRefused
				}
				if len(buf) > forwarded {
					if _, werr := upstream.Write(buf[forwarded:]); werr != nil {
						return werr
					}
				}
			}
			return rerr
		}
	}
}

// streamPermitted reports whether every located L7 command is a read
// or an allowlisted write. Anything else (unknown, non-allowlisted
// write) fails the stream closed.
func (h *WriteGatedHandler) streamPermitted(cmds []wire.L7Command) bool {
	for _, c := range cmds {
		switch c.Cat {
		case wire.CategoryRead:
			continue
		case wire.CategoryWrite:
			if h.cmdAllowed(c.Cmd) {
				continue
			}
			return false
		default: // CategoryUnknown
			return false
		}
	}
	return true
}

// cmdAllowed reports whether a mutating command is in the operator's
// allowlist.
func (h *WriteGatedHandler) cmdAllowed(c wire.Command) bool {
	for _, a := range h.Allowed {
		if a.command() == c {
			return true
		}
	}
	return false
}
