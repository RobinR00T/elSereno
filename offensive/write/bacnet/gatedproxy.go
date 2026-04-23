//go:build offensive

// Package bacnet implements the offensive write-gate UDP relay
// for BACnet/IP (ASHRAE 135) on port 47808.
//
// Architecture is the ADR-040 template adapted for UDP: per-
// session Authorise on the SHA-256 of a sorted allowlist, per-
// datagram filtering at wire-parse time. Like the IAX2 gate,
// each client.Read returns one complete datagram; we parse the
// BVLC + NPDU + APDU headers to decide the fate of each packet.
//
// Always-pass traffic:
//
//   - Non-BACnet bytes (first byte != 0x81): forward. The gate
//     refuses to second-guess upper layers we don't understand.
//   - Unconfirmed-Request PDUs (APDUType 0x1): Who-Is / I-Am /
//     Who-Has / I-Have / TimeSync / UnconfirmedCOVNotification /
//     UnconfirmedEventNotification / UnconfirmedPrivateTransfer /
//     UTCTimeSynchronization. Discovery / notification / presence
//     — no state changes.
//   - Simple-ACK / Complex-ACK / Segment-ACK / Error / Reject /
//     Abort PDUs: server-side responses, always passed through.
//   - Confirmed-Request PDUs with a *non-mutating* service choice
//     (ReadProperty, ReadPropertyMultiple, ReadRange,
//     AtomicReadFile, SubscribeCOV, GetAlarmSummary, etc.).
//
// Gated traffic — Confirmed-Request PDUs with a mutating service:
//   - AtomicWriteFile
//   - AddListElement / RemoveListElement
//   - CreateObject / DeleteObject
//   - WriteProperty / WritePropertyMultiple
//   - DeviceCommunicationControl  (can silence a device)
//   - ReinitializeDevice           (coldstart / warmstart)
//   - LifeSafetyOperation          (silence / unsilence alarms)
//
// Refusal path: emit an Abort-PDU with reason 5 (security-error)
// addressed to the client's source. Real BACnet stacks interpret
// this as "the server refused to process the request"; they do
// not retry.
//
// Out of scope for v1.4 chunk 6 (deferred to v1.5+): per-object
// / per-property allowlisting. The gate is service-choice only
// today; parsing the service-data ASN.1 tags to allow
// WriteProperty to specific Object_Identifiers is the next
// tightening.
package bacnet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"

	"local/elsereno/internal/protocols/bacnet/wire"
	"local/elsereno/offensive/confirm"
)

// AllowedService is one BACnet confirmed-service choice the
// operator has authorised for the session. ServiceChoice is the
// ASHRAE 135 Table 20-7 numeric — e.g. 15 for WriteProperty.
// Always-safe services (reads, unconfirmed, acks) don't need
// listing.
type AllowedService struct {
	ServiceChoice uint8
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedService) [32]byte {
	sorted := append([]AllowedService(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ServiceChoice < sorted[j].ServiceChoice })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedService) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// AbortReasonSecurity is ASHRAE 135 §20.1.9 abort reason 5.
const AbortReasonSecurity uint8 = 5

// WriteGatedHandler is the offensive replacement for the default
// BACnet fail-closed proxy.
type WriteGatedHandler struct {
	Target         string
	Allowed        []AllowedService
	Deriver        confirm.KeyDeriver
	Auditor        confirm.Auditor
	SessionConfirm confirm.Confirm

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
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

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("bacnet: write-gated proxy requires Authorise() first")

// maxDatagramSize caps a single BACnet/IP read at 1500 bytes
// (standard Ethernet MTU). BVLC Length is a uint16 so a rogue
// frame could claim 64 KiB; we refuse to allocate that much.
const maxDatagramSize = 1500

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
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
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
}

// forward reads datagrams from the client and routes per policy.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	buf := make([]byte, maxDatagramSize)
	for {
		n, readErr := client.Read(buf)
		if n > 0 {
			if err := h.routeFrame(buf[:n], upstream, clientWriter); err != nil {
				return err
			}
		}
		if readErr != nil {
			return readErr
		}
	}
}

// routeFrame decides what to do with one datagram.
func (h *WriteGatedHandler) routeFrame(frame []byte, upstream, clientWriter io.Writer) error {
	// Non-BACnet → forward. Don't gate what we can't parse.
	if len(frame) == 0 || frame[0] != wire.BVLCTypeBacnetIP {
		_, err := upstream.Write(frame)
		return err
	}
	apdu, invokeID, ok := extractAPDU(frame)
	if !ok {
		_, err := upstream.Write(frame)
		return err
	}
	typ, svc, hasSvc, perr := wire.ParseAPDUHeader(apdu)
	if perr != nil {
		_, err := upstream.Write(frame)
		return err
	}
	// Only confirmed-requests with a parseable service are gated.
	if typ != wire.APDUConfirmedRequest || !hasSvc {
		_, err := upstream.Write(frame)
		return err
	}
	if !wire.IsMutatingConfirmedService(svc) {
		_, err := upstream.Write(frame)
		return err
	}
	if h.isAllowed(svc) {
		_, err := upstream.Write(frame)
		return err
	}
	return h.writeAbortRefusal(clientWriter, invokeID)
}

// isAllowed reports whether the given confirmed service is in
// the session's allowlist.
func (h *WriteGatedHandler) isAllowed(s wire.ConfirmedService) bool {
	for _, a := range h.Allowed {
		if wire.ConfirmedService(a.ServiceChoice) == s {
			return true
		}
	}
	return false
}

// extractAPDU finds the APDU within a BVLC frame by walking past
// the BVLC + NPDU headers (honouring any optional routing
// fields).
//
// Returns (apdu, invokeID, ok). invokeID is 0 when the APDU
// isn't a confirmed-request.
func extractAPDU(frame []byte) ([]byte, uint8, bool) {
	if len(frame) < 4+2 { // BVLC(4) + minimal NPDU(2)
		return nil, 0, false
	}
	control := frame[5]
	offset := 4 + 2
	// Destination present: DNET(2) + DLEN(1) + DADR(DLEN) + Hops(1)
	if control&0x20 != 0 {
		if offset+3 > len(frame) {
			return nil, 0, false
		}
		dlen := int(frame[offset+2])
		offset += 3 + dlen + 1
	}
	// Source present: SNET(2) + SLEN(1) + SADR(SLEN)
	if control&0x08 != 0 {
		if offset+3 > len(frame) {
			return nil, 0, false
		}
		slen := int(frame[offset+2])
		offset += 3 + slen
	}
	if offset >= len(frame) {
		return nil, 0, false
	}
	apdu := frame[offset:]
	var invokeID uint8
	if len(apdu) >= 3 && wire.APDUType(apdu[0]>>4) == wire.APDUConfirmedRequest {
		invokeID = apdu[2]
	}
	return apdu, invokeID, true
}

// writeAbortRefusal emits a BVLC+NPDU+Abort-PDU datagram
// addressed to the client.
func (h *WriteGatedHandler) writeAbortRefusal(w io.Writer, invokeID uint8) error {
	abort := wire.BuildAbortPDU(invokeID, AbortReasonSecurity)
	body := make([]byte, 0, 4+2+len(abort))
	body = append(body, 0x00, 0x00, 0x00, 0x00) // BVLC placeholder
	body = append(body, 0x01, 0x00)             // NPDU version=1, control=0 (no routing)
	body = append(body, abort...)
	body[0] = wire.BVLCTypeBacnetIP
	body[1] = wire.BVLCOriginalUnicast
	// bodyLen is 4+2+3 = 9 by construction (fixed-size abort PDU).
	// The abort response always fits in < 256 bytes.
	body[2] = 0x00
	body[3] = byte(len(body) & 0xFF) //nolint:gosec // G115 — len(body) is a tiny constant-bounded value (≤ 32 bytes for the worst-case abort frame).
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("bacnet: write Abort refusal: %w", err)
	}
	return nil
}
