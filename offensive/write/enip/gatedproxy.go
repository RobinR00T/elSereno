//go:build offensive

package enip

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sort"

	enipwire "local/elsereno/internal/protocols/enip/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedCommand scopes an EIP encapsulation command the operator
// authorises for the session (e.g. CmdSendRRData).
type AllowedCommand struct {
	Cmd uint16
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedCommand) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Cmd < sorted[j].Cmd })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [2]byte
	for _, a := range sorted {
		binary.LittleEndian.PutUint16(buf[:], a.Cmd)
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedCommand) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "enip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// ErrSessionNotAuthorised is returned by Handle before Authorise.
var ErrSessionNotAuthorised = errors.New("enip: write-gated proxy requires Authorise() first")

// WriteGatedHandler routes ENIP writes through the ADR-039 wrapper.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedCommand
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every byte that crosses the gate is
	// timestamped + direction-tagged + persisted. Wrapping
	// happens BEFORE the encapsulation-packet parser reads,
	// so wire-aware allowlist routing is captured intact. Nil
	// disables recording — the gate behaves exactly as it did
	// pre-v1.30.
	Recorder *replay.Recorder

	authorised bool
}

// Authorise opens the proxy session.
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

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream, client) }()
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

func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		hdr, body, err := enipwire.ReadPacket(client)
		if err != nil {
			return err
		}
		if h.shouldForward(hdr) {
			buf := enipwire.MarshalHeader(hdr)
			if _, werr := upstream.Write(buf[:]); werr != nil {
				return werr
			}
			if len(body) > 0 {
				if _, werr := upstream.Write(body); werr != nil {
					return werr
				}
			}
			continue
		}
		if _, werr := clientWriter.Write(enipwire.BuildRefusal(hdr)); werr != nil {
			return werr
		}
	}
}

func (h *WriteGatedHandler) shouldForward(hdr enipwire.Header) bool {
	switch enipwire.Classify(hdr.Command) {
	case enipwire.CategoryRead:
		return true
	case enipwire.CategoryWrite:
		for _, a := range h.Allowed {
			if a.Cmd == hdr.Command {
				return true
			}
		}
		return false
	case enipwire.CategoryUnknown:
		return false
	}
	return false
}
