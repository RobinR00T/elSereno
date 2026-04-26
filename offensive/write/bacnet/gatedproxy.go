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

// AllowedCreateObject scopes a CreateObject confirmed-request
// (service 10) to a specific BACnetObjectType. v1.13 chunk 8
// adds object-type-level gating for the destructive service
// that creates new objects on the device.
//
// Semantics: when AllowedCreateObjects is non-empty, a
// CreateObject (svc 10) confirmed-request is forwarded ONLY
// when:
//
//   - its service choice is in Allowed (the v1.4 service-
//     level gate), AND
//   - the parsed objectSpecifier's BACnetObjectType is in
//     this list (regardless of which CHOICE form the request
//     uses — [0] objectType OR [1] objectIdentifier; the
//     instance is ignored at the gate).
//
// Empty list disables the per-create-object gate (CreateObject
// remains gated at service-choice level if 10 is in Allowed).
//
// Why type-only and not (type, instance)? Two reasons:
//
//  1. The most common CreateObject form is [0] objectType where
//     the device picks the instance — an operator can't pre-
//     declare a specific instance to allow.
//  2. The typical BAS use-case is "operator may create new
//     Schedule (type 17) objects on this device" — a TYPE-level
//     allowlist matches this exactly. Per-instance Create
//     allowlisting is unusual; v1.14+ may add it if asked.
//
// Kept SEPARATE from AllowedObjects (svc 15/16 property writes)
// and AllowedDeleteObjects (svc 11 deletes): a CreateObject
// of TypeX does not imply a DeleteObject of TypeX.Y or a
// WriteProperty of TypeX.Y.PresentValue.
type AllowedCreateObject struct {
	// ObjectType is ASHRAE 135 §21 BACnetObjectType — 10-bit
	// enum (e.g. 17 = Schedule, 19 = MultiStateValue).
	ObjectType uint16
}

// AllowedAtomicWriteFile scopes an AtomicWriteFile confirmed-
// request (service 7) to a specific File object instance. v1.13
// chunk 12 adds per-file-instance gating for the service that
// overwrites File objects on the device — firmware blobs,
// configuration files, and log files all live behind File
// objects on most BACnet devices.
//
// Semantics: when AllowedAtomicWriteFiles is non-empty, an
// AtomicWriteFile (svc 7) confirmed-request is forwarded ONLY
// when:
//
//   - its service choice is in Allowed (the v1.4 service-
//     level gate), AND
//   - the parsed fileIdentifier's ObjectInstance is in this
//     list (the ObjectType portion is implicitly 10 = File
//     per ASHRAE 135 §15.8; any other type fails closed).
//
// Empty list disables the per-file gate (AtomicWriteFile
// remains gated at service-choice level if 7 is in Allowed).
//
// Why per-instance and not (type, instance)? The fileIdentifier
// in AtomicWriteFile MUST be a File object (ObjectType 10) —
// no operator would ever want to allow writing to non-File
// objects via this RPC. Storing only the instance keeps the
// API simple; the parser validates the type itself.
//
// Why not also gate the access specifier (stream vs record,
// start position, record count)? That's wire-level minutiae —
// the operator's risk model is "may operator X overwrite
// firmware blob File#3?" not "may they overwrite bytes
// 100..200 of File#3?". Per-byte-range scoping has no
// operational use case in production.
//
// Kept SEPARATE from AllowedObjects (svc 15/16 property writes)
// and the other allowlists: writing to File#3 (firmware) is a
// fundamentally different operation from writing to
// AnalogValue#3 (sensor reading). The allowlists must not
// auto-grant each other.
type AllowedAtomicWriteFile struct {
	// Instance is the 22-bit BACnet File-object instance number
	// (0..4_194_303). Type is implicit (always 10 = File).
	Instance uint32
}

// AllowedLSOOperation scopes a LifeSafetyOperation confirmed-
// request (service 27) to a specific BACnetLifeSafetyOperation
// enum value. v1.13 chunk 11 adds operation-level gating for
// the most safety-critical BACnet service: silencing a fire-
// alarm panel during a real incident can lead to deaths.
//
// Semantics: when AllowedLSOOperations is non-empty, a
// LifeSafetyOperation (svc 27) confirmed-request is forwarded
// ONLY when:
//
//   - its service choice is in Allowed (the v1.4 service-
//     level gate), AND
//   - the parsed request enum value is in this list.
//
// Empty list disables the per-operation gate (LSO remains
// gated at service-choice level if 27 is in Allowed).
//
// Why operation-level? The 10-value enum has very different
// safety blast radii:
//
//   - 0 none: no-op marker (operationally safe but useless).
//   - 1/2/3 silence/silence-audible/silence-visual: HOSTILE
//     direction. Silencing a fire-alarm panel during an active
//     incident can cause loss of life. Operators on production
//     life-safety buses should NEVER allow these.
//   - 4/5/6 reset/reset-alarm/reset-fault: operationally
//     significant. Clear alarm/fault state — useful for post-
//     incident cleanup, dangerous if performed on an ACTIVE
//     alarm before the underlying cause is addressed.
//   - 7/8/9 unsilence/unsilence-audible/unsilence-visual: SAFE
//     direction. Undoes a prior silence — allows audible/
//     visual indicators to resume. Typical recovery action
//     when a panel was wrongly silenced.
//
// Typical operator pattern: allow 7/8/9 (unsilence — recovery
// direction) freely, allow 4/5/6 (reset) during incident
// response after manual verification, REFUSE 1/2/3 (silence)
// outright on production life-safety systems.
//
// The optional [3] objectIdentifier (which life-safety object
// the operation targets) is ignored at gate level — per-object
// scoping for LSO is a v1.14+ extension if operators ask. The
// requestingProcessIdentifier ([0]) and requestingSource ([1])
// are also ignored — those are operator-side metadata, not
// security-relevant at the gate.
//
// Kept SEPARATE from all other allowlists: this is a service-
// internal scoping dimension, orthogonal to property /
// delete / create / reinit / DCC lists.
type AllowedLSOOperation struct {
	// Operation is the ASHRAE 135 §21 BACnetLifeSafetyOperation
	// enum (0..9). See the wire.LSOOp* constants for the
	// labelled values.
	Operation uint8
}

// AllowedDCCState scopes a DeviceCommunicationControl
// confirmed-request (service 17) to a specific enableDisable
// enum value. v1.13 chunk 10 adds state-level gating for the
// service that can silence the device's BACnet communication.
//
// Semantics: when AllowedDCCStates is non-empty, a
// DeviceCommunicationControl (svc 17) confirmed-request is
// forwarded ONLY when:
//
//   - its service choice is in Allowed (the v1.4 service-
//     level gate), AND
//   - the parsed enableDisable enum value is in this list.
//
// Empty list disables the per-state gate (DeviceCommControl
// remains gated at service-choice level if 17 is in Allowed).
//
// Why state-level? The 3-state enum has very different blast
// radii:
//
//   - 0 enable: SAFE direction. Re-enables comms on a device
//     that was previously disabled — the typical recovery
//     action after an attacker silenced it.
//   - 1 disable: HOSTILE. Silences the device's BACnet
//     communication for the requested duration; blocks all
//     monitoring, alarms, and operational visibility during
//     incidents.
//   - 2 disableInitiation: SUBTLER attack. Device still
//     responds to read polls but will not INITIATE
//     notifications (no I-Am, no UnconfirmedCOVNotification,
//     no event broadcasts) — defenders lose proactive
//     awareness while polled metrics look normal.
//
// Typical operator pattern: allow state 0 (enable) only —
// permits recovery from an attacker-induced silence but
// refuses any attempt to silence a device. The optional
// timeDuration (context tag 0) and password (context tag 2)
// fields are ignored at gate level; the password is between
// the operator and the device's auth layer.
//
// Kept SEPARATE from all other allowlists: this is a service-
// internal scoping dimension, orthogonal to property /
// delete / create / reinit lists.
type AllowedDCCState struct {
	// State is the ASHRAE 135 §16.1 enableDisable enum (0..2).
	// See the wire.DCCState* constants for the labelled values.
	State uint8
}

// AllowedReinitState scopes a ReinitializeDevice confirmed-
// request (service 20) to a specific reinitializedStateOfDevice
// enum value. v1.13 chunk 9 adds state-level gating for the
// service that controls device coldstart/warmstart/backup.
//
// Semantics: when AllowedReinitStates is non-empty, a
// ReinitializeDevice (svc 20) confirmed-request is forwarded
// ONLY when:
//
//   - its service choice is in Allowed (the v1.4 service-
//     level gate), AND
//   - the parsed reinitializedStateOfDevice enum value is in
//     this list.
//
// Empty list disables the per-state gate (ReinitializeDevice
// remains gated at service-choice level if 20 is in Allowed).
//
// Why state-level? The 8-state enum has very different
// blast radii:
//
//   - 0 coldstart: WIPES runtime state.
//   - 1 warmstart: restarts the BACnet stack.
//   - 2..6 backup/restore lifecycle: bracket vendor backup
//     workflows; safe in isolation but destructive when
//     interleaved with normal traffic.
//   - 7 activate-changes: usually safe — post-config-write
//     refresh.
//
// Typical operator pattern: allow only state 7
// (activate-changes) during a maintenance window; refuse
// 0..6 outright. Per-instance scoping doesn't apply here —
// ReinitializeDevice always targets the device the proxy is
// forwarding to.
//
// Kept SEPARATE from all other allowlists: this is a service-
// internal scoping dimension, orthogonal to property /
// delete / create object lists.
type AllowedReinitState struct {
	// State is the ASHRAE 135 §16.4 reinitializedStateOfDevice
	// enum (0..7). See the wire.ReinitState* constants for the
	// labelled values.
	State uint8
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

// AllowlistHashWithCreateObjects is the v1.13 chunk-8 hash
// that adds the per-CreateObject (type) allowlist on top of
// the v1.13 chunk-7 layer. Backwards-compat ladder:
//
//   - empty createObjects → equals AllowlistHashWithDeleteObjects
//     (v1.13 chunk 7).
//   - empty createObjects + empty deleteObjects → equals
//     AllowlistHashWithObjects (v1.12).
//   - empty createObjects + empty deleteObjects + empty objects
//     → equals AllowlistHash (v1.4).
//
// All v1.4 → v1.13-chunk-7 confirm-tokens remain valid for
// operators who don't opt into per-create gating.
//
// Hash layout (when createObjects is non-empty):
//
//	AllowlistHashWithDeleteObjects output
//	  || 0xFD || (type BE16) × sorted_createObjects
//
// Separator 0xFD is below 0xFE (deletes) and 0xFF (per-property
// objects) — distinct sentinel byte. Per-entry is 2 bytes (type).
func AllowlistHashWithCreateObjects(target string, allowed []AllowedService, objects []AllowedObject, deleteObjects []AllowedDeleteObject, createObjects []AllowedCreateObject) [32]byte {
	if len(createObjects) == 0 {
		return AllowlistHashWithDeleteObjects(target, allowed, objects, deleteObjects)
	}
	sortedSvc := sortAllowedServices(allowed)
	sortedObj := sortAllowedObjects(objects)
	sortedDel := sortAllowedDeleteObjects(deleteObjects)
	sortedCre := append([]AllowedCreateObject(nil), createObjects...)
	sort.Slice(sortedCre, func(i, j int) bool {
		return sortedCre[i].ObjectType < sortedCre[j].ObjectType
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	writeObjectsBlock(h, sortedObj)
	writeDeleteObjectsBlock(h, sortedDel)
	writeCreateObjectsBlock(h, sortedCre)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// sortAllowedServices returns a deterministically sorted copy
// (by ServiceChoice ascending). Helper extracted to keep
// AllowlistHashWithCreateObjects under the funlen threshold.
func sortAllowedServices(in []AllowedService) []AllowedService {
	out := append([]AllowedService(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ServiceChoice < out[j].ServiceChoice })
	return out
}

// sortAllowedObjects returns a deterministically sorted copy
// (by Type, Instance, PropertyID ascending).
func sortAllowedObjects(in []AllowedObject) []AllowedObject {
	out := append([]AllowedObject(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObjectType != out[j].ObjectType {
			return out[i].ObjectType < out[j].ObjectType
		}
		if out[i].ObjectInstance != out[j].ObjectInstance {
			return out[i].ObjectInstance < out[j].ObjectInstance
		}
		return out[i].PropertyID < out[j].PropertyID
	})
	return out
}

// sortAllowedDeleteObjects returns a deterministically sorted
// copy (by Type, Instance ascending).
func sortAllowedDeleteObjects(in []AllowedDeleteObject) []AllowedDeleteObject {
	out := append([]AllowedDeleteObject(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObjectType != out[j].ObjectType {
			return out[i].ObjectType < out[j].ObjectType
		}
		return out[i].ObjectInstance < out[j].ObjectInstance
	})
	return out
}

// writeObjectsBlock writes the per-property objects block to h
// when non-empty. Separator 0xFF (v1.12 chunk 7).
func writeObjectsBlock(h hashWriter, sorted []AllowedObject) {
	if len(sorted) == 0 {
		return
	}
	_, _ = h.Write([]byte{0xFF})
	var u16 [2]byte
	var u32 [4]byte
	for _, o := range sorted {
		binary.BigEndian.PutUint16(u16[:], o.ObjectType)
		_, _ = h.Write(u16[:])
		binary.BigEndian.PutUint32(u32[:], o.ObjectInstance)
		_, _ = h.Write(u32[:])
		binary.BigEndian.PutUint32(u32[:], o.PropertyID)
		_, _ = h.Write(u32[:])
	}
}

// writeDeleteObjectsBlock writes the per-target deletes block
// when non-empty. Separator 0xFE (v1.13 chunk 7).
func writeDeleteObjectsBlock(h hashWriter, sorted []AllowedDeleteObject) {
	if len(sorted) == 0 {
		return
	}
	_, _ = h.Write([]byte{0xFE})
	var u16 [2]byte
	var u32 [4]byte
	for _, d := range sorted {
		binary.BigEndian.PutUint16(u16[:], d.ObjectType)
		_, _ = h.Write(u16[:])
		binary.BigEndian.PutUint32(u32[:], d.ObjectInstance)
		_, _ = h.Write(u32[:])
	}
}

// writeCreateObjectsBlock writes the per-create-type block.
// Separator 0xFD (v1.13 chunk 8). Caller must have already
// established len(sorted) > 0.
func writeCreateObjectsBlock(h hashWriter, sorted []AllowedCreateObject) {
	_, _ = h.Write([]byte{0xFD})
	var u16 [2]byte
	for _, c := range sorted {
		binary.BigEndian.PutUint16(u16[:], c.ObjectType)
		_, _ = h.Write(u16[:])
	}
}

// hashWriter is the minimal io.Writer subset the per-block
// helpers use — sha256.New() satisfies it via its hash.Hash
// interface. Defined locally so the helpers don't need to
// import "hash" + "io" just to share signatures.
type hashWriter interface {
	Write(p []byte) (int, error)
}

// SessionMutationWithCreateObjects is the v1.13 chunk-8
// mutation that mixes services + per-object + per-delete +
// per-create into the PayloadHash. Empty createObjects →
// degrades to SessionMutationWithDeleteObjects.
func SessionMutationWithCreateObjects(target string, allowed []AllowedService, objects []AllowedObject, deleteObjects []AllowedDeleteObject, createObjects []AllowedCreateObject) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithCreateObjects(target, allowed, objects, deleteObjects, createObjects),
	}
}

// AllowlistHashWithReinitStates is the v1.13 chunk-9 hash that
// adds the per-ReinitializeDevice state allowlist on top of
// the v1.13 chunk-8 layer. Backwards-compat ladder:
//
//   - empty reinitStates → equals AllowlistHashWithCreateObjects
//     (v1.13 chunk 8).
//   - empty reinitStates + empty createObjects → equals
//     AllowlistHashWithDeleteObjects (v1.13 chunk 7).
//   - all-empty → equals AllowlistHash (v1.4).
//
// All v1.4 → v1.13-chunk-8 confirm-tokens remain valid for
// operators who don't opt into per-state gating.
//
// Hash layout (when reinitStates is non-empty):
//
//	AllowlistHashWithCreateObjects output
//	  || 0xFC || (state byte) × sorted_reinitStates
//
// Separator 0xFC is below 0xFD (creates), 0xFE (deletes), and
// 0xFF (per-property objects). Per-entry is 1 byte (state enum).
func AllowlistHashWithReinitStates(target string, allowed []AllowedService, objects []AllowedObject, deleteObjects []AllowedDeleteObject, createObjects []AllowedCreateObject, reinitStates []AllowedReinitState) [32]byte {
	if len(reinitStates) == 0 {
		return AllowlistHashWithCreateObjects(target, allowed, objects, deleteObjects, createObjects)
	}
	sortedSvc := sortAllowedServices(allowed)
	sortedObj := sortAllowedObjects(objects)
	sortedDel := sortAllowedDeleteObjects(deleteObjects)
	sortedCre := sortAllowedCreateObjects(createObjects)
	sortedRei := append([]AllowedReinitState(nil), reinitStates...)
	sort.Slice(sortedRei, func(i, j int) bool {
		return sortedRei[i].State < sortedRei[j].State
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	writeObjectsBlock(h, sortedObj)
	writeDeleteObjectsBlock(h, sortedDel)
	if len(sortedCre) > 0 {
		writeCreateObjectsBlock(h, sortedCre)
	}
	writeReinitStatesBlock(h, sortedRei)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithReinitStates is the v1.13 chunk-9 mutation
// that mixes services + per-object + per-delete + per-create +
// per-reinit-state into the PayloadHash. Empty reinitStates →
// degrades to SessionMutationWithCreateObjects.
func SessionMutationWithReinitStates(target string, allowed []AllowedService, objects []AllowedObject, deleteObjects []AllowedDeleteObject, createObjects []AllowedCreateObject, reinitStates []AllowedReinitState) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithReinitStates(target, allowed, objects, deleteObjects, createObjects, reinitStates),
	}
}

// Allowlists bundles every per-service dimension into one
// arg so the v1.13 chunk-10+ hash + mutation factories don't
// need to grow a new function-parameter every time we add a
// dimension. v1.4 → v1.13-chunk-9 functions retain their
// per-dimension signatures for backwards-compat with operator
// code that constructs sessions piecewise.
type Allowlists struct {
	Services         []AllowedService
	Objects          []AllowedObject
	DeleteObjects    []AllowedDeleteObject
	CreateObjects    []AllowedCreateObject
	ReinitStates     []AllowedReinitState
	DCCStates        []AllowedDCCState
	LSOOperations    []AllowedLSOOperation
	AtomicWriteFiles []AllowedAtomicWriteFile
}

// AllowlistHashWithDCCStates is the v1.13 chunk-10 hash that
// adds the per-DeviceCommunicationControl state allowlist on
// top of the v1.13 chunk-9 layer. Backwards-compat ladder:
//
//   - empty DCCStates → equals AllowlistHashWithReinitStates
//     (v1.13 chunk 9).
//   - empty DCCStates + empty reinitStates → equals
//     AllowlistHashWithCreateObjects (v1.13 chunk 8).
//   - all-empty → equals AllowlistHash (v1.4).
//
// All v1.4 → v1.13-chunk-9 confirm-tokens remain valid for
// operators who don't opt into per-DCC-state gating.
//
// Hash layout (when DCCStates is non-empty):
//
//	AllowlistHashWithReinitStates output
//	  || 0xFB || (state byte) × sorted_DCCStates
//
// Separator 0xFB is below 0xFC (reinit), 0xFD (creates), 0xFE
// (deletes), and 0xFF (per-property objects). Per-entry is
// 1 byte (state enum 0..2).
func AllowlistHashWithDCCStates(target string, al Allowlists) [32]byte {
	if len(al.DCCStates) == 0 {
		return AllowlistHashWithReinitStates(target, al.Services, al.Objects, al.DeleteObjects, al.CreateObjects, al.ReinitStates)
	}
	sortedSvc := sortAllowedServices(al.Services)
	sortedObj := sortAllowedObjects(al.Objects)
	sortedDel := sortAllowedDeleteObjects(al.DeleteObjects)
	sortedCre := sortAllowedCreateObjects(al.CreateObjects)
	sortedRei := sortAllowedReinitStates(al.ReinitStates)
	sortedDCC := append([]AllowedDCCState(nil), al.DCCStates...)
	sort.Slice(sortedDCC, func(i, j int) bool {
		return sortedDCC[i].State < sortedDCC[j].State
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	writeObjectsBlock(h, sortedObj)
	writeDeleteObjectsBlock(h, sortedDel)
	if len(sortedCre) > 0 {
		writeCreateObjectsBlock(h, sortedCre)
	}
	if len(sortedRei) > 0 {
		writeReinitStatesBlock(h, sortedRei)
	}
	writeDCCStatesBlock(h, sortedDCC)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithDCCStates is the v1.13 chunk-10 mutation
// that mixes every per-service dimension (services + per-
// object + per-delete + per-create + per-reinit + per-DCC)
// into the PayloadHash. Empty DCCStates → degrades to
// SessionMutationWithReinitStates.
func SessionMutationWithDCCStates(target string, al Allowlists) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithDCCStates(target, al),
	}
}

// AllowlistHashWithLSOOps is the v1.13 chunk-11 hash that adds
// the per-LifeSafetyOperation allowlist on top of the v1.13
// chunk-10 layer. Backwards-compat ladder:
//
//   - empty LSOOperations → equals AllowlistHashWithDCCStates
//     (v1.13 chunk 10).
//   - all-empty (no LSO + no DCC + no reinit + no create + no
//     delete + no objects) → equals AllowlistHash (v1.4).
//
// All v1.4 → v1.13-chunk-10 confirm-tokens remain valid for
// operators who don't opt into per-LSO-operation gating.
//
// Hash layout (when LSOOperations is non-empty):
//
//	AllowlistHashWithDCCStates output
//	  || 0xFA || (op byte) × sorted_LSOOperations
//
// Separator 0xFA is below 0xFB (DCC), 0xFC (reinit), 0xFD
// (creates), 0xFE (deletes), and 0xFF (per-property objects).
// Per-entry is 1 byte (operation enum 0..9).
func AllowlistHashWithLSOOps(target string, al Allowlists) [32]byte {
	if len(al.LSOOperations) == 0 {
		return AllowlistHashWithDCCStates(target, al)
	}
	sortedSvc := sortAllowedServices(al.Services)
	sortedObj := sortAllowedObjects(al.Objects)
	sortedDel := sortAllowedDeleteObjects(al.DeleteObjects)
	sortedCre := sortAllowedCreateObjects(al.CreateObjects)
	sortedRei := sortAllowedReinitStates(al.ReinitStates)
	sortedDCC := sortAllowedDCCStates(al.DCCStates)
	sortedLSO := append([]AllowedLSOOperation(nil), al.LSOOperations...)
	sort.Slice(sortedLSO, func(i, j int) bool {
		return sortedLSO[i].Operation < sortedLSO[j].Operation
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	writeObjectsBlock(h, sortedObj)
	writeDeleteObjectsBlock(h, sortedDel)
	if len(sortedCre) > 0 {
		writeCreateObjectsBlock(h, sortedCre)
	}
	if len(sortedRei) > 0 {
		writeReinitStatesBlock(h, sortedRei)
	}
	if len(sortedDCC) > 0 {
		writeDCCStatesBlock(h, sortedDCC)
	}
	writeLSOOpsBlock(h, sortedLSO)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithLSOOps is the v1.13 chunk-11 mutation
// that mixes every per-service dimension (services + per-
// object + per-delete + per-create + per-reinit + per-DCC +
// per-LSO) into the PayloadHash. Empty LSOOperations →
// degrades to SessionMutationWithDCCStates.
func SessionMutationWithLSOOps(target string, al Allowlists) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithLSOOps(target, al),
	}
}

// AllowlistHashWithAWF is the v1.13 chunk-12 hash that adds
// the per-AtomicWriteFile-instance allowlist on top of the
// chunk-11 layer. Backwards-compat ladder:
//
//   - empty AtomicWriteFiles → equals AllowlistHashWithLSOOps
//     (v1.13 chunk 11).
//   - all-empty (no AWF + no LSO + ...) → equals AllowlistHash
//     (v1.4).
//
// All v1.4 → v1.13-chunk-11 confirm-tokens remain valid for
// operators who don't opt into per-file gating.
//
// Hash layout (when AtomicWriteFiles is non-empty):
//
//	AllowlistHashWithLSOOps output
//	  || 0xF9 || (instance BE32) × sorted_AtomicWriteFiles
//
// Separator 0xF9 is below 0xFA (LSO ops), 0xFB (DCC), 0xFC
// (reinit), 0xFD (creates), 0xFE (deletes), and 0xFF (per-
// property objects). Per-entry is 4 bytes (the 22-bit instance
// stored in a 4-byte big-endian word — the high 10 bits stay
// zero since File has no namespace prefix).
func AllowlistHashWithAWF(target string, al Allowlists) [32]byte {
	if len(al.AtomicWriteFiles) == 0 {
		return AllowlistHashWithLSOOps(target, al)
	}
	sortedSvc := sortAllowedServices(al.Services)
	sortedObj := sortAllowedObjects(al.Objects)
	sortedDel := sortAllowedDeleteObjects(al.DeleteObjects)
	sortedCre := sortAllowedCreateObjects(al.CreateObjects)
	sortedRei := sortAllowedReinitStates(al.ReinitStates)
	sortedDCC := sortAllowedDCCStates(al.DCCStates)
	sortedLSO := sortAllowedLSOOps(al.LSOOperations)
	sortedAWF := append([]AllowedAtomicWriteFile(nil), al.AtomicWriteFiles...)
	sort.Slice(sortedAWF, func(i, j int) bool {
		return sortedAWF[i].Instance < sortedAWF[j].Instance
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sortedSvc {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	writeObjectsBlock(h, sortedObj)
	writeDeleteObjectsBlock(h, sortedDel)
	if len(sortedCre) > 0 {
		writeCreateObjectsBlock(h, sortedCre)
	}
	if len(sortedRei) > 0 {
		writeReinitStatesBlock(h, sortedRei)
	}
	if len(sortedDCC) > 0 {
		writeDCCStatesBlock(h, sortedDCC)
	}
	if len(sortedLSO) > 0 {
		writeLSOOpsBlock(h, sortedLSO)
	}
	writeAWFBlock(h, sortedAWF)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutationWithAWF is the v1.13 chunk-12 mutation that
// mixes every per-service dimension into the PayloadHash.
// Empty AtomicWriteFiles → degrades to
// SessionMutationWithLSOOps.
func SessionMutationWithAWF(target string, al Allowlists) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithAWF(target, al),
	}
}

// sortAllowedLSOOps returns a deterministically sorted copy
// (by Operation ascending). Helper introduced alongside chunk
// 12 so AllowlistHashWithAWF can reuse the chunk-11 sort
// logic without re-stating it inline.
func sortAllowedLSOOps(in []AllowedLSOOperation) []AllowedLSOOperation {
	out := append([]AllowedLSOOperation(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Operation < out[j].Operation })
	return out
}

// writeAWFBlock writes the per-File-instance block. Separator
// 0xF9 (v1.13 chunk 12). Caller must have already established
// len(sorted) > 0.
func writeAWFBlock(h hashWriter, sorted []AllowedAtomicWriteFile) {
	_, _ = h.Write([]byte{0xF9})
	var u32 [4]byte
	for _, a := range sorted {
		binary.BigEndian.PutUint32(u32[:], a.Instance)
		_, _ = h.Write(u32[:])
	}
}

// sortAllowedDCCStates returns a deterministically sorted copy
// (by State ascending). Helper introduced alongside chunk 11
// so AllowlistHashWithLSOOps can reuse the chunk-10 sort logic
// without re-stating it inline.
func sortAllowedDCCStates(in []AllowedDCCState) []AllowedDCCState {
	out := append([]AllowedDCCState(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].State < out[j].State })
	return out
}

// writeLSOOpsBlock writes the per-operation block. Separator
// 0xFA (v1.13 chunk 11). Caller must have already established
// len(sorted) > 0.
func writeLSOOpsBlock(h hashWriter, sorted []AllowedLSOOperation) {
	_, _ = h.Write([]byte{0xFA})
	for _, l := range sorted {
		_, _ = h.Write([]byte{l.Operation})
	}
}

// sortAllowedReinitStates returns a deterministically sorted
// copy (by State ascending). Helper introduced alongside
// chunk 10 so AllowlistHashWithDCCStates can reuse the chunk-9
// sort logic without re-stating it inline.
func sortAllowedReinitStates(in []AllowedReinitState) []AllowedReinitState {
	out := append([]AllowedReinitState(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].State < out[j].State })
	return out
}

// writeDCCStatesBlock writes the per-DCC-state block. Separator
// 0xFB (v1.13 chunk 10). Caller must have already established
// len(sorted) > 0.
func writeDCCStatesBlock(h hashWriter, sorted []AllowedDCCState) {
	_, _ = h.Write([]byte{0xFB})
	for _, d := range sorted {
		_, _ = h.Write([]byte{d.State})
	}
}

// sortAllowedCreateObjects returns a deterministically sorted
// copy (by ObjectType ascending). Helper introduced alongside
// chunk 9 so AllowlistHashWithReinitStates can reuse the same
// sort pattern as the lower-layer hashes.
func sortAllowedCreateObjects(in []AllowedCreateObject) []AllowedCreateObject {
	out := append([]AllowedCreateObject(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ObjectType < out[j].ObjectType
	})
	return out
}

// writeReinitStatesBlock writes the per-state block. Separator
// 0xFC (v1.13 chunk 9). Caller must have already established
// len(sorted) > 0.
func writeReinitStatesBlock(h hashWriter, sorted []AllowedReinitState) {
	_, _ = h.Write([]byte{0xFC})
	for _, r := range sorted {
		_, _ = h.Write([]byte{r.State})
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
	// AllowedCreateObjects is the optional v1.13 chunk-8
	// per-create-type allowlist for CreateObject (service 10).
	// See AllowedCreateObject for semantics. Empty list
	// preserves service-choice-only gating for that service.
	AllowedCreateObjects []AllowedCreateObject
	// AllowedReinitStates is the optional v1.13 chunk-9
	// per-state allowlist for ReinitializeDevice (service 20).
	// See AllowedReinitState for semantics. Empty list preserves
	// service-choice-only gating for that service.
	AllowedReinitStates []AllowedReinitState
	// AllowedDCCStates is the optional v1.13 chunk-10 per-state
	// allowlist for DeviceCommunicationControl (service 17).
	// See AllowedDCCState for semantics. Empty list preserves
	// service-choice-only gating for that service.
	AllowedDCCStates []AllowedDCCState
	// AllowedLSOOperations is the optional v1.13 chunk-11
	// per-operation allowlist for LifeSafetyOperation (service
	// 27). See AllowedLSOOperation for semantics. Empty list
	// preserves service-choice-only gating for that service.
	AllowedLSOOperations []AllowedLSOOperation
	// AllowedAtomicWriteFiles is the optional v1.13 chunk-12
	// per-File-instance allowlist for AtomicWriteFile (service
	// 7). See AllowedAtomicWriteFile for semantics. Empty list
	// preserves service-choice-only gating for that service.
	AllowedAtomicWriteFiles []AllowedAtomicWriteFile
	Deriver                 confirm.KeyDeriver
	Auditor                 confirm.Auditor
	SessionConfirm          confirm.Confirm

	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithAWF(h.Target, Allowlists{
		Services:         h.Allowed,
		Objects:          h.AllowedObjects,
		DeleteObjects:    h.AllowedDeleteObjects,
		CreateObjects:    h.AllowedCreateObjects,
		ReinitStates:     h.AllowedReinitStates,
		DCCStates:        h.AllowedDCCStates,
		LSOOperations:    h.AllowedLSOOperations,
		AtomicWriteFiles: h.AllowedAtomicWriteFiles,
	})
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
// AllowedObjects; DeleteObject (11) uses AllowedDeleteObjects;
// CreateObject (10) uses AllowedCreateObjects; ReinitializeDevice
// (20) uses AllowedReinitStates; DeviceCommControl (17) uses
// AllowedDCCStates. Other mutating services keep service-only
// gating (no body inspection); they always pass through this
// helper. Per-service dispatch is split into per-list helpers so
// the function stays under gocyclo as we keep adding dimensions.
func (h *WriteGatedHandler) perObjectGatesAllow(svc wire.ConfirmedService, apdu []byte) bool {
	if !h.objectListGatesAllow(svc, apdu) {
		return false
	}
	if !h.stateListGatesAllow(svc, apdu) {
		return false
	}
	return true
}

// objectListGatesAllow runs the object-tuple-style gates: per-
// property writes (svc 15/16), per-target deletes (svc 11),
// per-create-types (svc 10), per-File-instance AtomicWriteFile
// (svc 7).
func (h *WriteGatedHandler) objectListGatesAllow(svc wire.ConfirmedService, apdu []byte) bool {
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
	if len(h.AllowedCreateObjects) > 0 && svc == wire.ConfirmedSvcCreateObject {
		if !h.createObjectAllowed(apdu) {
			return false
		}
	}
	if len(h.AllowedAtomicWriteFiles) > 0 && svc == wire.ConfirmedSvcAtomicWriteFile {
		if !h.atomicWriteFileAllowed(apdu) {
			return false
		}
	}
	return true
}

// atomicWriteFileAllowed parses the AtomicWriteFile body and
// reports whether the target File instance is in the
// operator's allowlist. Fail-closed on unparseable BER or
// when ObjectType != 10 (File).
func (h *WriteGatedHandler) atomicWriteFileAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	inst, ok := wire.ParseAtomicWriteFile(apdu[crHeader:])
	if !ok {
		return false
	}
	for _, a := range h.AllowedAtomicWriteFiles {
		if a.Instance == inst {
			return true
		}
	}
	return false
}

// stateListGatesAllow runs the enum-state-style gates: reinit
// states (svc 20), DCC states (svc 17), LSO operations (svc 27).
// These check a single enum byte each (LSO additionally walks
// past two preceding context-tagged primitives).
func (h *WriteGatedHandler) stateListGatesAllow(svc wire.ConfirmedService, apdu []byte) bool {
	if len(h.AllowedReinitStates) > 0 && svc == wire.ConfirmedSvcReinitializeDevice {
		if !h.reinitStateAllowed(apdu) {
			return false
		}
	}
	if len(h.AllowedDCCStates) > 0 && svc == wire.ConfirmedSvcDeviceCommControl {
		if !h.dccStateAllowed(apdu) {
			return false
		}
	}
	if len(h.AllowedLSOOperations) > 0 && svc == wire.ConfirmedSvcLifeSafetyOperation {
		if !h.lsoOperationAllowed(apdu) {
			return false
		}
	}
	return true
}

// lsoOperationAllowed parses the LifeSafetyOperation body and
// reports whether the requested BACnetLifeSafetyOperation enum
// value is in the operator's per-operation allowlist. Fail-
// closed on unparseable BER or unknown enum value.
func (h *WriteGatedHandler) lsoOperationAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	op, ok := wire.ParseLifeSafetyOperation(apdu[crHeader:])
	if !ok {
		return false
	}
	for _, a := range h.AllowedLSOOperations {
		if a.Operation == op {
			return true
		}
	}
	return false
}

// dccStateAllowed parses the DeviceCommunicationControl body
// and reports whether the requested enableDisable enum value
// is in the operator's per-state allowlist. Fail-closed on
// unparseable BER or unknown enum value.
func (h *WriteGatedHandler) dccStateAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	state, ok := wire.ParseDeviceCommControl(apdu[crHeader:])
	if !ok {
		return false
	}
	for _, a := range h.AllowedDCCStates {
		if a.State == state {
			return true
		}
	}
	return false
}

// reinitStateAllowed parses the ReinitializeDevice body and
// reports whether the requested reinitializedStateOfDevice
// enum value is in the operator's per-state allowlist. Fail-
// closed on unparseable BER or unknown enum value.
func (h *WriteGatedHandler) reinitStateAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	state, ok := wire.ParseReinitializeDevice(apdu[crHeader:])
	if !ok {
		return false
	}
	for _, a := range h.AllowedReinitStates {
		if a.State == state {
			return true
		}
	}
	return false
}

// createObjectAllowed parses the CreateObject body and reports
// whether the requested ObjectType is in the operator's
// per-create-type allowlist. Fail-closed on unparseable BER.
//
// The gate matches by type only — instance is ignored even
// when the [1] choice form encodes one. See AllowedCreateObject
// for the design rationale.
func (h *WriteGatedHandler) createObjectAllowed(apdu []byte) bool {
	const crHeader = 4
	if len(apdu) <= crHeader {
		return false
	}
	objType, ok := wire.ParseCreateObject(apdu[crHeader:])
	if !ok {
		return false
	}
	for _, a := range h.AllowedCreateObjects {
		if a.ObjectType == objType {
			return true
		}
	}
	return false
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
