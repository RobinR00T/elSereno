//go:build offensive

// Package redlion implements the offensive write-gate proxy for the
// Red Lion Crimson v3 (CR3) link protocol on TCP/789. Crimson is the
// engineering link to Red Lion Controls' G3 / Graphite / FlexEdge /
// DA-50N / Sixnet HMIs and RTUs; a config-chunk upload, register push,
// or value write over TCP/789 rewrites the panel's configuration or
// firmware on a live device.
//
// This completes the relay that internal/protocols/redlion deferred:
// its default build is fingerprint-only and explicitly notes "a relay
// arrives with the future offensive plugin". The gate is that plugin.
//
// Framing is deterministic (unlike CODESYS): CR3 is length-prefixed
// (2-byte big-endian body length at offset 0), so the handler reads
// discrete frames via internal/protocols/redlion/wire.ReadFrame and
// gates each by its Type opcode (offset 4). Read opcodes pass; a
// mutating opcode passes only when allowlisted; everything else
// (including handshake / no-payload opcodes whose semantics the public
// dissector does not establish) is refused. CR3 has no documented
// per-request NAK, so a refusal CLOSES the connection (fail-closed),
// mirroring the GE-SRTP handler.
package redlion

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	"local/elsereno/internal/protocols/redlion/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedType scopes one CR3 Type opcode the operator has authorised to
// forward. Read opcodes always pass and need no entry; entries here
// open specific mutating (or dissector-unclassified) opcodes that would
// otherwise be refused.
type AllowedType struct {
	Type uint16
}

// AllowlistHash returns the deterministic SHA-256 over target + the
// sorted allowlist so the operator's dry-run token is stable
// regardless of order.
func AllowlistHash(target string, allowed []AllowedType) [32]byte {
	sorted := append([]AllowedType(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Type < sorted[j].Type })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var b [2]byte
	for _, a := range sorted {
		binary.BigEndian.PutUint16(b[:], a.Type)
		_, _ = h.Write(b[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation for the
// CR3 proxy allowlist.
func SessionMutation(target string, allowed []AllowedType) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "redlion",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default CR3
// fail-closed TCP proxy.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedType
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
var ErrSessionNotAuthorised = errors.New("redlion: write-gated proxy requires Authorise() first")

// ErrRefused ends the session when a client frame is refused. CR3 has
// no clean per-request refusal frame, so the gate drops the connection
// (fail-closed). The client reconnects and resyncs.
var ErrRefused = errors.New("redlion: CR3 frame refused by write-gate")

// Handle implements core.ProxyHandler. Client->upstream is gated
// frame-by-frame; upstream->client responses are a straight copy.
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

// forward reads one length-prefixed CR3 frame at a time and routes
// each per policy. A refused frame returns ErrRefused, which tears the
// session down.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer) error {
	for {
		frame, err := wire.ReadFrame(client)
		if err != nil {
			return err
		}
		t, ok := wire.ExtractType(frame)
		if ok && wire.ClassifyType(t) == wire.CategoryRead {
			if _, werr := upstream.Write(frame); werr != nil {
				return werr
			}
			continue
		}
		if ok && h.typeAllowed(t) {
			if _, werr := upstream.Write(frame); werr != nil {
				return werr
			}
			continue
		}
		return ErrRefused
	}
}

// typeAllowed reports whether a mutating / unclassified CR3 Type is in
// the operator's allowlist.
func (h *WriteGatedHandler) typeAllowed(t wire.PacketType) bool {
	for _, a := range h.Allowed {
		if wire.PacketType(a.Type) == t {
			return true
		}
	}
	return false
}
