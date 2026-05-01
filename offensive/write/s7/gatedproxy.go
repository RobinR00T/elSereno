//go:build offensive

package s7

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"

	s7wire "local/elsereno/internal/protocols/s7/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedFunction scopes the S7 function codes the operator
// authorises for the session (e.g. FuncWriteVar, FuncPLCStop).
type AllowedFunction struct {
	FC s7wire.FunctionCode
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist. Independent of insertion order.
func AllowlistHash(target string, allowed []AllowedFunction) [32]byte {
	sorted := append([]AllowedFunction(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].FC < sorted[j].FC })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{byte(a.FC)})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedFunction) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "s7",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// ErrSessionNotAuthorised is returned by Handle before Authorise.
var ErrSessionNotAuthorised = errors.New("s7: write-gated proxy requires Authorise() first")

// WriteGatedHandler routes S7 writes through the ADR-039 triple-
// confirm wrapper. Session-level Authorise runs once; per-frame
// decisions consult the authorised allowlist.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedFunction
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every TPKT envelope that crosses the gate is
	// timestamped + direction-tagged + persisted. Wrapping
	// happens BEFORE the TPKT/COTP parser reads, so wire-aware
	// allowlist routing is captured intact. Nil disables
	// recording — the gate behaves exactly as it did pre-v1.30.
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

// forward reads one TPKT envelope at a time; forwards allowed
// functions and refuses anything else with the same S7 AckData
// err-class 0x85 / code 0x01 the default build uses.
func (h *WriteGatedHandler) forward(client io.Reader, upstream io.Writer, clientWriter io.Writer) error {
	for {
		tpkt, err := s7wire.ReadTPKT(client)
		if err != nil {
			return err
		}
		if h.shouldForward(tpkt.Payload) {
			if werr := s7wire.WriteTPKT(upstream, tpkt.Payload); werr != nil {
				return werr
			}
			continue
		}
		refusal := s7wire.BuildRefusalPayload(innerPDU(tpkt.Payload))
		if werr := s7wire.WriteTPKT(clientWriter, refusal); werr != nil {
			return werr
		}
	}
}

// shouldForward returns true when the COTP payload represents a
// CategoryRead S7 function OR a CategoryWrite whose FC appears in
// the authorised allowlist.
func (h *WriteGatedHandler) shouldForward(payload []byte) bool {
	t, ok := s7wire.COTPType(payload)
	if !ok {
		return false
	}
	if t != s7wire.COTPData {
		// Non-DT COTP PDUs (CR, CC, DR) forward untouched so the
		// handshake completes.
		return true
	}
	fc, ok := s7wire.ExtractFunctionCode(innerPDU(payload))
	if !ok {
		return false
	}
	switch s7wire.Classify(fc) {
	case s7wire.CategoryRead:
		return true
	case s7wire.CategoryWrite:
		for _, a := range h.Allowed {
			if a.FC == fc {
				return true
			}
		}
		return false
	case s7wire.CategoryUnknown:
		return false
	}
	return false
}

// innerPDU slices the S7 PDU portion out of a COTP DT TPKT payload
// using the same layout the default write-ban handler uses.
func innerPDU(payload []byte) []byte {
	if len(payload) < 3 {
		return payload
	}
	li := int(payload[0])
	s7Start := li + 1
	if s7Start >= len(payload) {
		return payload
	}
	return payload[s7Start:]
}
