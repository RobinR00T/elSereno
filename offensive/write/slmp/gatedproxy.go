//go:build offensive

// Package slmp implements the offensive write-gate proxy for the
// MELSEC SLMP protocol on TCP/5007. SLMP is the modern (2014+)
// Mitsubishi Electric factory protocol across the iQ-R, iQ-F, Q, L,
// and FX-series PLCs and many compatible HMIs and motion
// controllers; a Device Write, Remote Stop, or Remote Reset changes
// physical process state on a live controller.
//
// Architecture mirrors offensive/write/s7 (a TCP length-prefixed
// WriteGatedHandler on the ADR-040 template):
//
//   - Per-session Authorise on the SHA-256 of a sorted command
//     allowlist (ADR-039 triple-confirm).
//   - Per-frame classification: one 3E-binary frame at a time via
//     wire.ReadFrame; reads always pass, a mutating command passes
//     only when the operator allowlisted that command code, and
//     everything else is refused.
//   - Refusal is a NATIVE SLMP response (end code 0xC059, "command
//     cannot be executed") written back to the client and never
//     forwarded upstream, so an intelligent client sees an
//     intelligible rejection (ADR-040). The two client-writing
//     goroutines share a locked writer so refusal and response frames
//     never interleave on the TCP stream.
//
// Out of scope for this cycle: per-device-address narrowing within an
// allowed Device Write (the SLMP analogue of the s7 per-item gate).
package slmp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"sync"

	"local/elsereno/internal/protocols/slmp/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedCommand scopes one SLMP command code the operator has
// authorised to forward. Read commands (Device Read, Read CPU Model
// Name, ...) always pass and need no entry; entries here open
// specific MUTATING commands (e.g. 0x1401 Device Write Batch) that
// would otherwise be refused.
type AllowedCommand struct {
	Command uint16
}

// AllowedDevice scopes an allowed Device Write Batch (0x1401,
// subcommand 0x0000) to a specific SLMP device code (e.g. 0xA8 = D
// data register, 0x90 = M relay, W word, etc.). When the operator
// supplies any AllowedDevice, a Device Write Batch is admitted only if
// its device code matches one AND it uses the parseable word-unit
// subcommand; anything else (other subcommand, short frame) is
// refused. An empty list keeps the command-level gate.
type AllowedDevice struct {
	Code byte
}

// allowlistSeparatorDevice guards the device section of the hash so it
// can't collide with a command's little-endian bytes; 0xE1 is above
// every SLMP command byte pair used here.
const allowlistSeparatorDevice byte = 0xE1

// AllowlistHash returns the deterministic SHA-256 over target + the
// sorted command allowlist + the sorted device allowlist so the
// operator's dry-run token is stable regardless of input order.
func AllowlistHash(target string, allowed []AllowedCommand, devices []AllowedDevice) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Command < sorted[j].Command })
	sortedDevs := append([]AllowedDevice(nil), devices...)
	sort.Slice(sortedDevs, func(i, j int) bool { return sortedDevs[i].Code < sortedDevs[j].Code })

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var b [2]byte
	for _, a := range sorted {
		binary.LittleEndian.PutUint16(b[:], a.Command)
		_, _ = h.Write(b[:])
	}
	if len(sortedDevs) > 0 {
		_, _ = h.Write([]byte{allowlistSeparatorDevice})
		for _, d := range sortedDevs {
			_, _ = h.Write([]byte{d.Code})
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation for the
// SLMP proxy allowlist (commands + optional per-device scoping).
func SessionMutation(target string, allowed []AllowedCommand, devices []AllowedDevice) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "slmp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed, devices),
	}
}

// WriteGatedHandler is the offensive replacement for the default SLMP
// fail-closed TCP proxy.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	AllowedDevices []AllowedDevice
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
	m := SessionMutation(h.Target, h.Allowed, h.AllowedDevices)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise has
// not been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("slmp: write-gated proxy requires Authorise() first")

// lockedWriter serialises the two goroutines that write back to the
// client (the upstream->client response copy and the refusal path)
// so their frames never interleave on the shared TCP stream.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// Handle implements core.ProxyHandler.
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

// forward reads one 3E-binary frame at a time and routes each per
// policy.
func (h *WriteGatedHandler) forward(client io.Reader, clientOut, upstream io.Writer) error {
	for {
		frame, err := wire.ReadFrame(client)
		if err != nil {
			return err
		}
		if werr := h.routeFrame(frame, clientOut, upstream); werr != nil {
			return werr
		}
	}
}

// routeFrame decides one SLMP frame. Reads pass upstream; allowlisted
// mutating commands pass upstream; anything else (a non-allowlisted
// mutation, an unknown command, or a frame too short to classify) is
// refused with a native SLMP response and never forwarded.
func (h *WriteGatedHandler) routeFrame(frame []byte, clientOut, upstream io.Writer) error {
	cmd, ok := wire.ExtractCommand(frame)
	if ok && wire.Classify(cmd) == wire.CategoryRead {
		_, werr := upstream.Write(frame)
		return werr
	}
	if ok && h.commandAllowed(cmd) {
		// Per-device scoping (opt-in): a command-allowlisted Device
		// Write Batch is additionally narrowed to the operator's
		// allowed device codes. Fail-closed: a frame whose device code
		// can't be parsed (other subcommand, short) is refused.
		if cmd == wire.CmdDeviceWriteBatch && len(h.AllowedDevices) > 0 && !h.deviceAllowed(frame) {
			_, werr := clientOut.Write(wire.BuildRefusal(frame))
			return werr
		}
		_, werr := upstream.Write(frame)
		return werr
	}
	_, werr := clientOut.Write(wire.BuildRefusal(frame))
	return werr
}

// commandAllowed reports whether a mutating / unknown command is in
// the operator's allowlist.
func (h *WriteGatedHandler) commandAllowed(cmd wire.Command) bool {
	for _, a := range h.Allowed {
		if wire.Command(a.Command) == cmd {
			return true
		}
	}
	return false
}

// deviceAllowed reports whether a Device Write Batch frame targets one
// of the operator-allowed device codes. An unparseable device code
// (non-word subcommand, short frame) returns false: the gate never
// admits what it cannot verify.
func (h *WriteGatedHandler) deviceAllowed(frame []byte) bool {
	code, ok := wire.WriteBatchDeviceCode(frame)
	if !ok {
		return false
	}
	for _, d := range h.AllowedDevices {
		if d.Code == code {
			return true
		}
	}
	return false
}
