package wire

// APDUType identifies the high-nibble of the first APDU byte. It
// classifies the BACnet application PDU as a request, reply, or
// ack.
//
// Layout (ASHRAE 135 §20.1.1): the top 4 bits of APDU byte 0 are
// the PDU type; the low 4 bits carry flags (segmented, more-
// follows, SA) for confirmed requests, or reserved for others.
type APDUType byte

// APDU type values (ASHRAE 135 Table 20-1).
const (
	APDUConfirmedRequest   APDUType = 0x0 // confirmed-Request-PDU
	APDUUnconfirmedRequest APDUType = 0x1 // unconfirmed-Request-PDU
	APDUSimpleAck          APDUType = 0x2 // simple-ACK-PDU
	APDUComplexAck         APDUType = 0x3 // complex-ACK-PDU
	APDUSegmentAck         APDUType = 0x4 // segment-ACK-PDU
	APDUError              APDUType = 0x5 // error-PDU
	APDUReject             APDUType = 0x6 // reject-PDU
	APDUAbort              APDUType = 0x7 // abort-PDU
)

// ConfirmedService is a confirmed-service choice (ASHRAE 135 Table
// 20-7). Only the subset of services the gate needs to classify
// is enumerated; the numeric values come straight from the spec.
type ConfirmedService uint8

// Confirmed service choices.
const (
	// Alarm / event family.
	ConfirmedSvcAcknowledgeAlarm         ConfirmedService = 0
	ConfirmedSvcCovNotification          ConfirmedService = 1
	ConfirmedSvcEventNotification        ConfirmedService = 2
	ConfirmedSvcGetAlarmSummary          ConfirmedService = 3
	ConfirmedSvcGetEnrollmentSummary     ConfirmedService = 4
	ConfirmedSvcSubscribeCOV             ConfirmedService = 5
	ConfirmedSvcAtomicReadFile           ConfirmedService = 6
	ConfirmedSvcAtomicWriteFile          ConfirmedService = 7  // GATED
	ConfirmedSvcAddListElement           ConfirmedService = 8  // GATED
	ConfirmedSvcRemoveListElement        ConfirmedService = 9  // GATED
	ConfirmedSvcCreateObject             ConfirmedService = 10 // GATED
	ConfirmedSvcDeleteObject             ConfirmedService = 11 // GATED
	ConfirmedSvcReadProperty             ConfirmedService = 12
	ConfirmedSvcReadPropertyMultiple     ConfirmedService = 14
	ConfirmedSvcWriteProperty            ConfirmedService = 15 // GATED
	ConfirmedSvcWritePropertyMultiple    ConfirmedService = 16 // GATED
	ConfirmedSvcDeviceCommControl        ConfirmedService = 17 // GATED (very dangerous — can silence a device)
	ConfirmedSvcConfirmedPrivateTransfer ConfirmedService = 18
	ConfirmedSvcConfirmedTextMessage     ConfirmedService = 19
	ConfirmedSvcReinitializeDevice       ConfirmedService = 20 // GATED (coldstart / warmstart)
	ConfirmedSvcVTOpen                   ConfirmedService = 21
	ConfirmedSvcVTClose                  ConfirmedService = 22
	ConfirmedSvcVTData                   ConfirmedService = 23
	ConfirmedSvcReadRange                ConfirmedService = 26
	ConfirmedSvcLifeSafetyOperation      ConfirmedService = 27 // GATED (silence / unsilence)
	ConfirmedSvcSubscribeCOVProperty     ConfirmedService = 28
	ConfirmedSvcGetEventInformation      ConfirmedService = 29
)

// IsMutatingConfirmedService reports whether the given confirmed
// service is a state-changing operation that the gate must
// authorise explicitly. The safe-read set passes unconditionally.
//
// The authoritative reference is ASHRAE 135 §13 (Object Services).
// The set below is conservative: anything that writes, deletes,
// creates, or controls device behaviour is gated. Alarm-ack is
// excluded because it's operationally required and does not
// change persistent configuration (only event state).
func IsMutatingConfirmedService(s ConfirmedService) bool {
	switch s { //nolint:exhaustive // non-listed services are non-mutating by definition of this predicate
	case ConfirmedSvcAtomicWriteFile,
		ConfirmedSvcAddListElement,
		ConfirmedSvcRemoveListElement,
		ConfirmedSvcCreateObject,
		ConfirmedSvcDeleteObject,
		ConfirmedSvcWriteProperty,
		ConfirmedSvcWritePropertyMultiple,
		ConfirmedSvcDeviceCommControl,
		ConfirmedSvcReinitializeDevice,
		ConfirmedSvcLifeSafetyOperation:
		return true
	}
	return false
}

// ParseAPDUHeader extracts the PDU type (top nibble) + optional
// confirmed-service choice. Inputs: the APDU bytes (everything
// after the 2-byte NPDU header).
//
// Returns:
//
//	typ             the PDU's APDUType
//	service         the ConfirmedService when typ ==
//	                APDUConfirmedRequest; undefined otherwise
//	hasService      true iff service was extractable
//	err             non-nil only when the buffer is too short
//	                to even read byte 0
//
// Confirmed-request layout (ASHRAE 135 §20.1.2):
//
//	byte 0:  (type<<4) | (flags 0..7)
//	byte 1:  max-segments<<4 | max-response
//	byte 2:  invoke-id
//	byte 3:  service-choice
//
// Unconfirmed-request (ASHRAE 135 §20.1.3):
//
//	byte 0:  type<<4
//	byte 1:  service-choice (NOT a ConfirmedService — different
//	         enum; we don't gate unconfirmed)
func ParseAPDUHeader(apdu []byte) (typ APDUType, service ConfirmedService, hasService bool, err error) {
	if len(apdu) < 1 {
		return 0, 0, false, ErrShortAPDU
	}
	typ = APDUType(apdu[0] >> 4)
	if typ != APDUConfirmedRequest {
		return typ, 0, false, nil
	}
	// Confirmed request: byte 3 is the service choice.
	if len(apdu) < 4 {
		return typ, 0, false, ErrShortAPDU
	}
	return typ, ConfirmedService(apdu[3]), true, nil
}

// BuildAbortPDU returns an Abort-PDU (APDUType 0x7) targeting the
// given invoke-id with the given reason. Reasons (ASHRAE 135
// §20.1.9):
//
//	0 = other
//	1 = buffer-overflow
//	2 = invalid-APDU-in-this-state
//	3 = preempted-by-higher-priority-task
//	4 = segmentation-not-supported
//	5 = security-error
//	9 = application-exceeded-reply-time
//
// We use 5 (security-error) for a gate-refusal; it's the most
// operator-intelligible reason ("the relay refused for security").
//
// Layout (2 bytes):
//
//	byte 0: (0x7<<4) | 0 (server-abort flag = 0)
//	byte 1: invoke-id
//	byte 2: abort-reason
func BuildAbortPDU(invokeID uint8, reason uint8) []byte {
	return []byte{
		byte(APDUAbort) << 4,
		invokeID,
		reason,
	}
}

// ErrShortAPDU is returned by ParseAPDUHeader on truncated input.
var ErrShortAPDU = &shortAPDUError{}

type shortAPDUError struct{}

func (*shortAPDUError) Error() string { return "bacnet/wire: APDU too short" }
