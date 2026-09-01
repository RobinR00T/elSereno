//go:build offensive

// Package gesrtp implements the offensive write-gate proxy for the GE
// Service Request Transfer Protocol (SRTP) on TCP/18245. SRTP is the
// factory protocol across GE / Emerson (ex-GE-Fanuc) 90-30 / 90-70 /
// RX3i / RX7i PACSystems PLCs; a WRITE_SYS_MEM, SET_PLC_RUN, PROG_LOAD
// or TOGGLE_FORCE changes physical process state on a live controller.
//
// Architecture mirrors offensive/write/slmp (a TCP WriteGatedHandler
// on the ADR-040 template), with two SRTP-specific choices:
//
//   - Framing is a fixed 56-byte mailbox per PDU (the Palatis
//     dissector consumes exactly 56 bytes; a small write's data is
//     inline in the mailbox). The service code and its category come
//     from internal/protocols/gesrtp/wire, derived from that
//     validated dissector.
//   - SRTP has no clean per-request "permission denied" frame, so a
//     refusal CLOSES the connection (fail-closed) rather than
//     fabricating an error mailbox. The client reconnects and resyncs.
//
// Out of scope: large multi-packet writes whose data spans additional
// mailboxes are gated per-frame; an unrecognised continuation mailbox
// simply refuses (closing the session), never forwards.
package gesrtp

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"

	"local/elsereno/internal/protocols/gesrtp/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedService scopes one SRTP service-request code the operator has
// authorised to forward. Read services (READ_SYS_MEM, GET_INFO, ...)
// always pass and need no entry; entries here open specific mutating
// services (e.g. 0x07 WRITE_SYS_MEM, 0x23 SET_PLC_RUN) that would
// otherwise be refused.
type AllowedService struct {
	Code byte
}

// AllowlistHash returns the deterministic SHA-256 over target + the
// sorted allowlist so the operator's dry-run token is stable
// regardless of order.
func AllowlistHash(target string, allowed []AllowedService) [32]byte {
	sorted := append([]AllowedService(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Code < sorted[j].Code })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.Code})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation for the
// SRTP proxy allowlist.
func SessionMutation(target string, allowed []AllowedService) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "gesrtp",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// WriteGatedHandler is the offensive replacement for the default SRTP
// fail-closed TCP proxy.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedService
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
var ErrSessionNotAuthorised = errors.New("gesrtp: write-gated proxy requires Authorise() first")

// ErrRefused ends the session when a client mailbox is refused. SRTP
// has no clean per-request refusal frame, so the gate drops the
// connection (fail-closed).
var ErrRefused = errors.New("gesrtp: mailbox refused by write-gate")

// Handle implements core.ProxyHandler. Client->upstream is gated
// mailbox-by-mailbox; upstream->client responses are a straight copy.
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

// forward reads one 56-byte mailbox at a time and routes each per
// policy. A refused mailbox returns ErrRefused, which tears the
// session down.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer) error {
	for {
		mailbox, err := wire.ReadMailbox(client)
		if err != nil {
			return err
		}
		code, ok := wire.ExtractServiceCode(mailbox)
		if ok && wire.Classify(code) == wire.CategoryRead {
			if _, werr := upstream.Write(mailbox); werr != nil {
				return werr
			}
			continue
		}
		if ok && h.serviceAllowed(code) {
			if _, werr := upstream.Write(mailbox); werr != nil {
				return werr
			}
			continue
		}
		return ErrRefused
	}
}

// serviceAllowed reports whether a mutating / unknown service code is
// in the operator's allowlist.
func (h *WriteGatedHandler) serviceAllowed(code wire.ServiceCode) bool {
	for _, a := range h.Allowed {
		if wire.ServiceCode(a.Code) == code {
			return true
		}
	}
	return false
}
