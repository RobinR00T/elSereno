//go:build offensive

// Package finsudp implements the offensive write-gate proxy for the
// Omron FINS protocol on UDP/9600. FINS is the factory-network
// service shared across Omron CJ / CS / CP / NJ / NX-series PLCs and
// some HMIs; a FINS Memory Area Write, RUN/STOP, or Forced Set/Reset
// changes physical process state on a live controller.
//
// Architecture mirrors offensive/write/knxip (UDP-aware
// WriteGatedHandler on the ADR-040 template):
//
//   - Per-session Authorise on the SHA-256 of a sorted command
//     allowlist (ADR-039 triple-confirm).
//   - Per-datagram classification at wire-parse time (no per-frame
//     token): reads always pass; a mutating command passes only when
//     the operator allowlisted that exact (MRC, SRC); everything else
//     is refused.
//   - Refusal is a NATIVE FINS response (end code 0x2101, "cannot
//     write / write-protected") written back to the client, never
//     forwarded upstream, so an intelligent client sees an
//     intelligible error instead of a silent drop (ADR-040).
//
// Out of scope for this cycle (slated future): per-memory-area /
// per-address narrowing within an allowed Memory Area Write, the FINS
// finer tier analogous to knxip's group-address gate.
package finsudp

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"
	"sync"

	"local/elsereno/internal/protocols/finsudp/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedCommand scopes one FINS (MRC, SRC) command the operator has
// authorised to forward. Read commands (Memory Area Read, Controller
// Data Read, Clock Read, ...) always pass and need no entry; entries
// here open specific MUTATING commands (e.g. MRC=0x01 SRC=0x02,
// Memory Area Write) that would otherwise be refused.
type AllowedCommand struct {
	MRC byte
	SRC byte
}

func (a AllowedCommand) command() wire.Command { return wire.MakeCommand(a.MRC, a.SRC) }

// AllowlistHash returns the deterministic SHA-256 over target + the
// sorted allowlist, so the operator's dry-run token is stable
// regardless of the order the commands were supplied on the CLI.
func AllowlistHash(target string, allowed []AllowedCommand) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].MRC != sorted[j].MRC {
			return sorted[i].MRC < sorted[j].MRC
		}
		return sorted[i].SRC < sorted[j].SRC
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.MRC, a.SRC})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation for the
// FINS proxy allowlist.
func SessionMutation(target string, allowed []AllowedCommand) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "finsudp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default FINS
// fail-closed UDP proxy.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional record-replay hook for capturing the
	// proxy session to an NDJSON file. Nil = no recording.
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

// ErrSessionNotAuthorised is returned by Handle when Authorise has
// not been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("finsudp: write-gated proxy requires Authorise() first")

// maxDatagramSize caps one FINS/UDP read at the Ethernet MTU. FINS
// datagrams (including a full data-memory Memory Area Write) live
// well under 1500 bytes.
const maxDatagramSize = 1500

// lockedWriter serialises the two goroutines that write back to the
// client (the upstream->client response copy and the refusal path)
// so their datagrams never interleave on a shared writer.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Handle implements core.ProxyHandler. It fans the two directions
// into goroutines: client->upstream is gated frame-by-frame; the
// upstream->client responses are copied through the same locked
// writer the refusal path uses.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	var cw io.ReadWriter = client
	var uw io.ReadWriter = upstream
	if h.Recorder != nil {
		cw = h.Recorder.WrapClient(cw)
		uw = h.Recorder.WrapUpstream(uw)
	}
	lc := &lockedWriter{w: cw}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(cw, lc, uw) }()
	go func() {
		_, err := io.Copy(lc, uw)
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

// forward reads client datagrams and routes each per policy.
func (h *WriteGatedHandler) forward(client io.Reader, clientOut, upstream io.Writer) error {
	buf := make([]byte, maxDatagramSize)
	for {
		n, readErr := client.Read(buf)
		if n > 0 {
			if err := h.routeFrame(buf[:n], clientOut, upstream); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

// routeFrame decides one FINS datagram. Reads pass upstream;
// allowlisted mutating commands pass upstream; anything else (a
// non-allowlisted mutation, an unknown command, or a frame too short
// to classify) is refused with a native FINS response and never
// forwarded.
func (h *WriteGatedHandler) routeFrame(frame []byte, clientOut, upstream io.Writer) error {
	cmd, ok := wire.ExtractCommand(frame)
	if !ok {
		return h.refuse(frame, clientOut)
	}
	if wire.Classify(cmd) == wire.CategoryRead {
		_, werr := upstream.Write(frame)
		return werr
	}
	if h.commandAllowed(cmd) {
		_, werr := upstream.Write(frame)
		return werr
	}
	return h.refuse(frame, clientOut)
}

// refuse writes a native FINS refusal back to the client and does not
// forward the frame upstream. A client-side write error ends the
// session.
func (h *WriteGatedHandler) refuse(frame []byte, clientOut io.Writer) error {
	_, werr := clientOut.Write(wire.BuildRefusal(frame))
	return werr
}

// commandAllowed reports whether a mutating / unknown command is in
// the operator's allowlist.
func (h *WriteGatedHandler) commandAllowed(cmd wire.Command) bool {
	for _, a := range h.Allowed {
		if a.command() == cmd {
			return true
		}
	}
	return false
}
