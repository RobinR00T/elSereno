package wire

// CIP service-code classification, scoped by object class.
//
// The EIP encapsulation layer (Classify in categories.go) can only
// tell "read-class listing traffic" from "an envelope that may carry
// a CIP service" (SendRRData / SendUnitData). It cannot say WHAT the
// carried service does. This file adds that missing layer for the
// detection / exposure-scoring path (it builds nothing on the wire and
// speaks to no device: it only labels a (service, class) pair).
//
// Design lesson (source: Pascal Ackerman, "CIP one-pager", 2026;
// cross-checked against ODVA CIP Vol 1 Appendix A common services and
// the Rockwell Logix 5000 Data Access manual):
//
//   - A CIP service code is CLASS-SCOPED. The same byte means different
//     things depending on the object class it is addressed to. 0x52 is
//     Unconnected_Send inside the Connection Manager (class 0x06) but
//     Read Tag Fragmented against a tag/Symbol object (class 0x6B).
//     0x4E is Forward_Close in the Connection Manager but a vendor
//     service elsewhere. Matching the service byte with no class
//     context is the classic false-positive generator, so this
//     classifier reports whether its verdict was actually class-scoped
//     (see the bool return of ClassifyCIPService).
//
//   - The generic common services (0x01..0x1C, CIP Vol 1 Appendix A)
//     DO carry a class-independent meaning and are labelled directly.
//
// Nothing here mutates a device. It is a labelling table for detection,
// the same role a Zeek ICSNPP or Suricata signature plays.

// ServiceKind is the operational class of a CIP service, for scoring.
type ServiceKind int

// ServiceKind values, ordered by escalating operational impact.
const (
	// ServiceKindUnknown is the fallback: an unrecognised service, or
	// one whose meaning cannot be resolved without more context (e.g.
	// Multiple Service Packet, which nests sub-requests). Scoring
	// treats it conservatively (not "clean").
	ServiceKindUnknown ServiceKind = iota
	// ServiceKindRead covers reconnaissance / data-read services:
	// Get Attribute(s), Read Tag, symbol enumeration. Non-mutating,
	// but the visibility signal the false-zero rule depends on.
	ServiceKindRead
	// ServiceKindConnection covers Connection Manager session setup /
	// teardown: Forward_Open, Forward_Close, Unconnected_Send, Large
	// Forward_Open. Not a data write, but the second visibility signal
	// the false-zero rule depends on (an implicit-I/O connection is
	// the usual carrier for cyclic writes we never see explicitly).
	ServiceKindConnection
	// ServiceKindWrite covers data mutation: Set Attribute(s),
	// Write Tag, Apply Attributes, Create, Delete.
	ServiceKindWrite
	// ServiceKindAdmin covers device state changes with the widest
	// blast radius: Reset, Start, Stop, Restore, Save. These are the
	// services an exposure audit must never treat as background noise.
	ServiceKindAdmin
)

// String renders a ServiceKind for logs and reports.
func (k ServiceKind) String() string {
	switch k {
	case ServiceKindRead:
		return "read"
	case ServiceKindConnection:
		return "connection"
	case ServiceKindWrite:
		return "write"
	case ServiceKindAdmin:
		return "admin"
	default:
		return "unknown"
	}
}

// Well-known CIP object classes referenced by the class-scoped table.
// (ODVA CIP Vol 1, object library.)
const (
	// ClassIdentity is object class 0x01: firmware, serial, state.
	// Reset here power-cycles / factory-resets the device.
	ClassIdentity uint32 = 0x01
	// ClassMessageRouter is object class 0x02.
	ClassMessageRouter uint32 = 0x02
	// ClassConnectionManager is object class 0x06: the class that owns
	// Forward_Open / Forward_Close / Unconnected_Send.
	ClassConnectionManager uint32 = 0x06
	// ClassSymbol is object class 0x6B: the Logix tag/symbol namespace.
	// Enumerating it dumps every tag name (process design leak); Write
	// Tag against it mutates live process variables.
	ClassSymbol uint32 = 0x6B
	// ClassTemplate is object class 0x6C: tag structure templates.
	ClassTemplate uint32 = 0x6C
)

// Generic CIP common services (CIP Vol 1 Appendix A). These carry a
// class-independent meaning, so ClassifyCIPService resolves them
// without needing the object class.
const (
	svcGetAttributesAll      byte = 0x01
	svcSetAttributesAll      byte = 0x02
	svcGetAttributeList      byte = 0x03
	svcSetAttributeList      byte = 0x04
	svcReset                 byte = 0x05
	svcStart                 byte = 0x06
	svcStop                  byte = 0x07
	svcCreate                byte = 0x08
	svcDelete                byte = 0x09
	svcMultipleServicePacket byte = 0x0A
	svcApplyAttributes       byte = 0x0D
	svcGetAttributeSingle    byte = 0x0E
	svcSetAttributeSingle    byte = 0x10
	svcRestore               byte = 0x15
	svcSave                  byte = 0x16
	svcNOP                   byte = 0x17
)

// Vendor-specific service codes (Rockwell Logix). Their meaning is only
// well-defined against the tag/Symbol namespace or the Connection
// Manager, which is exactly why they must be class-scoped.
const (
	svcReadTag            byte = 0x4C
	svcReadTagFragmented  byte = 0x52 // also Unconnected_Send in ConnMgr
	svcWriteTag           byte = 0x4D
	svcWriteTagFragmented byte = 0x53
	svcForwardClose       byte = 0x4E // in ConnMgr; vendor service elsewhere
	svcForwardOpen        byte = 0x54
	svcLargeForwardOpen   byte = 0x5B
	svcReadModifyWriteTag byte = 0x4E // Logix RMW shares 0x4E: see class scoping
)

// ClassifyCIPService returns the operational kind of a CIP service byte
// addressed to the object in t, plus whether the verdict was actually
// class-scoped.
//
// The second return is the anti-false-positive signal from the source
// one-pager: when it is false, the kind was inferred from the service
// byte alone (either a class-independent common service, or an
// ambiguous byte we resolved to its most common meaning without a
// class). A detection rule should down-weight, not drop, an unscoped
// write/admin hit, and should never raise a "clean" verdict from the
// absence of one.
func ClassifyCIPService(service byte, t EPathTarget) (ServiceKind, bool) {
	if kind, scoped, ok := classifyCommonCIPService(service, t.HasClass); ok {
		return kind, scoped
	}
	return classifyVendorCIPService(service, t)
}

// classifyCommonCIPService labels the generic CIP common services (CIP
// Vol 1 Appendix A), which carry a class-independent meaning. The third
// return reports whether service was one of them; false means the
// caller must fall through to the class-scoped vendor path.
func classifyCommonCIPService(service byte, hasClass bool) (ServiceKind, bool, bool) {
	switch service {
	case svcGetAttributesAll, svcGetAttributeList, svcGetAttributeSingle, svcNOP:
		return ServiceKindRead, true, true
	case svcSetAttributesAll, svcSetAttributeList, svcSetAttributeSingle,
		svcApplyAttributes, svcCreate, svcDelete:
		return ServiceKindWrite, true, true
	case svcReset, svcStart, svcStop, svcRestore, svcSave:
		// State-changing. On the Identity object (0x01) this is the
		// device-wide reset/stop the audit cares about most; on any
		// class it is admin-grade, so the kind is stable, but we flag
		// the reading as class-scoped only when a class was present.
		return ServiceKindAdmin, hasClass, true
	case svcMultipleServicePacket:
		// Carries nested sub-requests; a single label would be a lie.
		// Left Unknown so scoring stays conservative.
		return ServiceKindUnknown, false, true
	}
	return ServiceKindUnknown, false, false
}

// classifyVendorCIPService labels the vendor-specific service range,
// which is genuinely class-scoped: the same byte flips meaning between
// the Connection Manager and the tag namespace. Without a usable class
// the ambiguous bytes stay Unknown.
func classifyVendorCIPService(service byte, t EPathTarget) (ServiceKind, bool) {
	if !t.HasClass {
		return classifyVendorByteOnly(service)
	}
	switch t.Class {
	case ClassConnectionManager:
		switch service {
		case svcForwardOpen, svcLargeForwardOpen, svcForwardClose, svcReadTagFragmented:
			// 0x52 here is Unconnected_Send (a connection carrier),
			// NOT Read Tag Fragmented.
			return ServiceKindConnection, true
		}
	case ClassSymbol, ClassTemplate:
		switch service {
		case svcReadTag, svcReadTagFragmented:
			return ServiceKindRead, true
		case svcWriteTag, svcWriteTagFragmented, svcReadModifyWriteTag:
			// 0x4E here is Read-Modify-Write Tag (a write), NOT
			// Forward_Close.
			return ServiceKindWrite, true
		}
	default:
		// Some other object: the tag services are not defined here, so
		// fall back to the byte-only guess with classScoped=false.
		return classifyVendorByteOnly(service)
	}
	return ServiceKindUnknown, false
}

// classifyVendorByteOnly is the best-effort labelling of a vendor
// service byte with no usable class context. The ambiguous bytes 0x4E
// and 0x52 cannot be safely labelled and stay Unknown; the scoped flag
// is always false so scoring down-weights the guess.
func classifyVendorByteOnly(service byte) (ServiceKind, bool) {
	switch service {
	case svcReadTag:
		return ServiceKindRead, false
	case svcWriteTag, svcWriteTagFragmented:
		return ServiceKindWrite, false
	case svcForwardOpen, svcLargeForwardOpen:
		return ServiceKindConnection, false
	default:
		// 0x4E and 0x52 are the textbook ambiguous bytes.
		return ServiceKindUnknown, false
	}
}

// ServiceObservation counts the CIP service kinds seen against one
// target over an observation window (a proxy session, a captured
// trace, a scripted probe sweep). It is the input to the false-zero
// rule below.
type ServiceObservation struct {
	Reads       int
	Connections int
	Writes      int
	Admin       int
	Unknown     int
}

// Observe increments the counter for one classified service.
func (o *ServiceObservation) Observe(k ServiceKind) {
	switch k {
	case ServiceKindRead:
		o.Reads++
	case ServiceKindConnection:
		o.Connections++
	case ServiceKindWrite:
		o.Writes++
	case ServiceKindAdmin:
		o.Admin++
	default:
		o.Unknown++
	}
}

// ExposureVerdict is the outcome of the false-zero rule.
type ExposureVerdict int

// ExposureVerdict values.
const (
	// VerdictBlind means no service of any kind was observed. This is
	// the false zero: it is NOT evidence of a clean device, only of a
	// vantage point that saw nothing. Treated as inconclusive.
	VerdictBlind ExposureVerdict = iota
	// VerdictClean means read and/or connection traffic was observed
	// (so the vantage point had visibility) AND no write or admin
	// service appeared. A clean bill of health that the data actually
	// supports.
	VerdictClean
	// VerdictActive means at least one write or admin (Reset / Stop /
	// Start) service was observed. The exposure is real and live.
	VerdictActive
)

// String renders an ExposureVerdict for reports.
func (v ExposureVerdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictActive:
		return "active"
	default:
		return "blind"
	}
}

// Verdict applies the false-zero rule to the observation.
//
// From the source one-pager: "the absence of write/stop/reset services
// only indicates a clean state if reads / Forward_Opens are non-zero."
// So a zero write count is only reassuring once we can prove we would
// have seen a write had one happened, which the presence of reads or
// connections demonstrates. With no traffic at all, the honest answer
// is "blind", never "clean".
func (o ServiceObservation) Verdict() ExposureVerdict {
	if o.Writes > 0 || o.Admin > 0 {
		return VerdictActive
	}
	if o.Reads > 0 || o.Connections > 0 {
		return VerdictClean
	}
	return VerdictBlind
}
