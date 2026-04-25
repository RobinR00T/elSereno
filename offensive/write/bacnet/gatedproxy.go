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
	"encoding/binary"
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

// AllowedObject scopes a WriteProperty request to a specific
// (ObjectType, ObjectInstance, PropertyID) tuple. v1.12 chunk 7:
// the per-object tightening on top of the v1.4 service-choice
// gate.
//
// Semantics: when the handler's AllowedObjects field is non-
// empty, a WriteProperty (service 15) confirmed-request is
// forwarded ONLY when:
//
//   - its service choice is in Allowed (the v1.4 service-level
//     gate), AND
//   - the parsed target's (ObjectType, ObjectInstance, PropertyID)
//     EXACTLY matches one of these entries.
//
// Other mutating services (WritePropertyMultiple, CreateObject,
// DeleteObject, ReinitializeDevice, DeviceCommunicationControl,
// LifeSafetyOperation, AtomicWriteFile, AddListElement,
// RemoveListElement) are NOT constrained by AllowedObjects —
// their request structures differ. Operators who want per-object
// scoping on those services will need v1.13+ (or keep using
// service-only gating for them today).
//
// Empty list disables the per-object gate (WriteProperty still
// allowed service-wide if 15 is in Allowed).
type AllowedObject struct {
	// ObjectType is ASHRAE 135 §21 BACnetObjectType — 10-bit
	// enum (e.g. 0 = AnalogInput, 2 = BinaryOutput, 8 = Device).
	ObjectType uint16
	// ObjectInstance is the 22-bit instance number (0..4_194_303).
	ObjectInstance uint32
	// PropertyID is the ASHRAE 135 BACnetPropertyIdentifier enum
	// (e.g. 85 = PresentValue, 87 = Priority-Array).
	PropertyID uint32
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

// AllowedDeleteObject scopes a DeleteObject confirmed-request
// (service 11) to a specific (ObjectType, ObjectInstance) pair.
// v1.13 chunk 7 adds object-level gating for the destructive
// service that doesn't carry a property dimension.
//
// Semantics: when AllowedDeleteObjects is non-empty, a
// DeleteObject (svc 11) confirmed-request is forwarded ONLY
// when:
//
//   - its service choice is in Allowed (the v1.4 service-
//     level gate), AND
//   - the parsed target's (ObjectType, ObjectInstance) EXACTLY
//     matches one of these entries.
//
// Empty list disables the per-target-delete gate (DeleteObject
// remains gated at service-choice level if 11 is in Allowed).
//
// Kept SEPARATE from AllowedObjects (the property-level list
// for svc 15/16) because the semantics differ: deleting an
// object is more destructive than writing one of its
// properties, and operators may want to allow property writes
// to objects they DON'T want deleted (typical BAS pattern).
type AllowedDeleteObject struct {
	ObjectType     uint16
	ObjectInstance uint32
}

// AllowlistHashWithObjects is the v1.12 chunk-7 hash that also
// folds per-object (type, instance, property) entries into the
// PayloadHash. Backwards compat: empty objects → equals
// AllowlistHash(target, services) (v1.4 tokens remain valid for
// operators not opting into per-object gating).
//
// Hash layout (when objects is non-empty):
//
//	target || 0x00 || SVC × sorted_services
//	               || 0xFF || (type BE16 || instance BE32 || property BE32) × sorted_objects
//
// 0xFF separator is outside the valid service-choice range
// (0..255 fits in one byte; the separator is a sentinel distinct
// from any ServiceChoice byte). Per-entry: 2-byte type + 4-byte
// instance + 4-byte property = 10 bytes.
func AllowlistHashWithObjects(target string, allowed []AllowedService, objects []AllowedObject) [32]byte {
	if len(objects) == 0 {
		return AllowlistHash(target, allowed)
	}
	sortedSvc := append([]AllowedService(nil), allowed...)
	sort.Slice(sortedSvc, func(i, j int) bool { return sortedSvc[i].ServiceChoice < sortedSvc[j].ServiceChoice })
	sortedObj := append([]AllowedObject(nil), objects...)
	sort.Slice(sortedObj, func(i, j int) bool {
		if sortedObj[i].ObjectType != sortedObj[j].ObjectType {
			return sortedObj[i].ObjectType < sortedObj[j].ObjectType
		}
		if sortedObj[i].ObjectInstance != sortedObj[j].ObjectInstance {
			return sortedObj[i].ObjectInstance < sortedObj[j].ObjectInstance
		}
		return sortedObj[i].PropertyID < sortedObj[j].PropertyID
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	_, _ = h.Write([]byte{0xFF})
	var u16 [2]byte
	var u32 [4]byte
	for _, o := range sortedObj {
		binary.BigEndian.PutUint16(u16[:], o.ObjectType)
		_, _ = h.Write(u16[:])
		binary.BigEndian.PutUint32(u32[:], o.ObjectInstance)
		_, _ = h.Write(u32[:])
		binary.BigEndian.PutUint32(u32[:], o.PropertyID)
		_, _ = h.Write(u32[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithObjects is the v1.12 chunk-7 mutation that
// mixes services + per-object allowlist into the PayloadHash.
// Empty objects → degrades to SessionMutation.
func SessionMutationWithObjects(target string, allowed []AllowedService, objects []AllowedObject) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithObjects(target, allowed, objects),
	}
}

// AllowlistHashWithDeleteObjects is the v1.13 chunk-7 hash that
// adds the per-DeleteObject (type, instance) allowlist on top
// of the v1.12 layer. Backwards-compat ladder: empty
// deleteObjects → equals AllowlistHashWithObjects (v1.12);
// empty deleteObjects AND empty objects → equals AllowlistHash
// (v1.4). v1.4–v1.12 confirm-tokens remain valid.
//
// Hash layout (when deleteObjects is non-empty):
//
//	AllowlistHashWithObjects output
//	  || 0xFE || (type BE16 || instance BE32) × sorted_deleteObjects
//
// 0xFE separator is below the 0xFF used by v1.12 chunk-7's
// objects block, and per-entry is 6 bytes (2 type + 4 instance).
func AllowlistHashWithDeleteObjects(target string, allowed []AllowedService, objects []AllowedObject, deleteObjects []AllowedDeleteObject) [32]byte {
	if len(deleteObjects) == 0 {
		return AllowlistHashWithObjects(target, allowed, objects)
	}
	sortedSvc := append([]AllowedService(nil), allowed...)
	sort.Slice(sortedSvc, func(i, j int) bool { return sortedSvc[i].ServiceChoice < sortedSvc[j].ServiceChoice })
	sortedObj := append([]AllowedObject(nil), objects...)
	sort.Slice(sortedObj, func(i, j int) bool {
		if sortedObj[i].ObjectType != sortedObj[j].ObjectType {
			return sortedObj[i].ObjectType < sortedObj[j].ObjectType
		}
		if sortedObj[i].ObjectInstance != sortedObj[j].ObjectInstance {
			return sortedObj[i].ObjectInstance < sortedObj[j].ObjectInstance
		}
		return sortedObj[i].PropertyID < sortedObj[j].PropertyID
	})
	sortedDel := append([]AllowedDeleteObject(nil), deleteObjects...)
	sort.Slice(sortedDel, func(i, j int) bool {
		if sortedDel[i].ObjectType != sortedDel[j].ObjectType {
			return sortedDel[i].ObjectType < sortedDel[j].ObjectType
		}
		return sortedDel[i].ObjectInstance < sortedDel[j].ObjectInstance
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	if len(sortedObj) > 0 {
		_, _ = h.Write([]byte{0xFF})
		var u16 [2]byte
		var u32 [4]byte
		for _, o := range sortedObj {
			binary.BigEndian.PutUint16(u16[:], o.ObjectType)
			_, _ = h.Write(u16[:])
			binary.BigEndian.PutUint32(u32[:], o.ObjectInstance)
			_, _ = h.Write(u32[:])
			binary.BigEndian.PutUint32(u32[:], o.PropertyID)
			_, _ = h.Write(u32[:])
		}
	}
	_, _ = h.Write([]byte{0xFE})
	var u16 [2]byte
	var u32 [4]byte
	for _, d := range sortedDel {
		binary.BigEndian.PutUint16(u16[:], d.ObjectType)
		_, _ = h.Write(u16[:])
		binary.BigEndian.PutUint32(u32[:], d.ObjectInstance)
		_, _ = h.Write(u32[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithDeleteObjects is the v1.13 chunk-7
// mutation that mixes services + per-object + per-delete into
// the PayloadHash. Empty deleteObjects → degrades to
// SessionMutationWithObjects.
func SessionMutationWithDeleteObjects(target string, allowed []AllowedService, objects []AllowedObject, deleteObjects []AllowedDeleteObject) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithDeleteObjects(target, allowed, objects, deleteObjects),
	}
}

// AbortReasonSecurity is ASHRAE 135 §20.1.9 abort reason 5.
const AbortReasonSecurity uint8 = 5

// WriteGatedHandler is the offensive replacement for the default
// BACnet fail-closed proxy.
type WriteGatedHandler struct {
	Target  string
	Allowed []AllowedService
	// AllowedObjects is the optional v1.12 chunk-7 per-object
	// allowlist for WriteProperty (service 15) and the v1.13
	// chunk-3 extension for WritePropertyMultiple (service 16).
	// See AllowedObject for semantics. Empty list preserves
	// v1.4 service-choice-only gating for those services.
	AllowedObjects []AllowedObject
	// AllowedDeleteObjects is the optional v1.13 chunk-7
	// per-target-delete allowlist for DeleteObject (service 11).
	// See AllowedDeleteObject for semantics. Empty list
	// preserves service-choice-only gating for that service.
	AllowedDeleteObjects []AllowedDeleteObject
	Deriver              confirm.KeyDeriver
	Auditor              confirm.Auditor
	SessionConfirm       confirm.Confirm

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithDeleteObjects(h.Target, h.Allowed, h.AllowedObjects, h.AllowedDeleteObjects)
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
	if !h.isAllowed(svc) {
		return h.writeAbortRefusal(clientWriter, invokeID)
	}
	if !h.perObjectGatesAllow(svc, apdu) {
		return h.writeAbortRefusal(clientWriter, invokeID)
	}
	_, err := upstream.Write(frame)
	return err
}

// perObjectGatesAllow runs the per-service body checks for the
// services that ship them. WriteProperty (15) + WPM (16) share
// AllowedObjects; DeleteObject (11) uses AllowedDeleteObjects.
// Other mutating services keep service-only gating (no body
// inspection); they always pass through this helper.
func (h *WriteGatedHandler) perObjectGatesAllow(svc wire.ConfirmedService, apdu []byte) bool {
	if len(h.AllowedObjects) > 0 {
		switch svc { //nolint:exhaustive // services not listed don't carry a per-property body the gate inspects
		case wire.ConfirmedSvcWriteProperty:
			if !h.writePropertyObjectAllowed(apdu) {
				return false
			}
		case wire.ConfirmedSvcWritePropertyMultiple:
			if !h.writePropertyMultipleObjectsAllowed(apdu) {
				return false
			}
		}
	}
	if len(h.AllowedDeleteObjects) > 0 && svc == wire.ConfirmedSvcDeleteObject {
		if !h.deleteObjectAllowed(apdu) {
			return false
		}
	}
	return true
}

// deleteObjectAllowed parses the DeleteObject body and reports
// whether the target (ObjectType, ObjectInstance) is in the
// operator's per-delete allowlist. Fail-closed on unparseable
// BER.
func (h *WriteGatedHandler) deleteObjectAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	target, ok := wire.ParseDeleteObject(apdu[crHeader:])
	if !ok {
		return false
	}
	for _, a := range h.AllowedDeleteObjects {
		if a.ObjectType == target.ObjectType &&
			a.ObjectInstance == target.ObjectInstance {
			return true
		}
	}
	return false
}

// writePropertyObjectAllowed parses the WriteProperty body and
// reports whether the target (ObjectType, ObjectInstance,
// PropertyID) is in the operator's allowlist. Fail-closed on
// unparseable BER.
func (h *WriteGatedHandler) writePropertyObjectAllowed(apdu []byte) bool {
	// Skip the 4-byte confirmed-request header.
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	target, ok := wire.ParseWriteProperty(apdu[crHeader:])
	if !ok {
		return false
	}
	return h.objectInAllowlist(target)
}

// writePropertyMultipleObjectsAllowed parses the WPM body and
// reports whether EVERY (type, instance, property) tuple in
// the request is in the operator's allowlist (same list as
// for WriteProperty). Fail-closed on unparseable BER, empty
// list, or any out-of-allowlist entry.
//
// v1.13 chunk 3: complement to writePropertyObjectAllowed for
// the second-most-common BACnet write surface.
func (h *WriteGatedHandler) writePropertyMultipleObjectsAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	targets, ok := wire.ParseWritePropertyMultiple(apdu[crHeader:])
	if !ok || len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if !h.objectInAllowlist(t) {
			return false
		}
	}
	return true
}

// objectInAllowlist reports whether one (type, instance,
// property) tuple is in AllowedObjects. Shared between the
// WriteProperty and WritePropertyMultiple gate checks.
func (h *WriteGatedHandler) objectInAllowlist(t wire.WritePropertyTarget) bool {
	for _, a := range h.AllowedObjects {
		if a.ObjectType == t.ObjectType &&
			a.ObjectInstance == t.ObjectInstance &&
			a.PropertyID == t.PropertyID {
			return true
		}
	}
	return false
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
