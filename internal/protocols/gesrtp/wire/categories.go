package wire

import "io"

// GE-SRTP service-request classification for the proxy write-gating
// matrix (ADR-040).
//
// SOURCE: the byte layout and the service-code map below are taken
// from the Palatis/packet-ge-srtp Wireshark dissector (a public
// reverse-engineering of the proprietary GE-SRTP wire), cross-checked
// against the SRTP memory-acquisition paper. The service code sits at
// a msg-type-dependent offset inside the 56-byte mailbox:
//
//	offset 31  msg type   (0xC0 SHORT, 0x80 EXTENDED, 0xD4/0xD1/0x94
//	                       are ACK/ERR responses)
//	SHORT:    offset 42   service request code, 43 segment selector
//	EXTENDED: offset 50   service request code, 51 segment selector
//
// NOTE: the fingerprint plugin's ServiceLongStatus (0x21) is labelled
// "Read PLC Long Status" from the nmap/metasploit lineage, but this
// dissector labels 0x21 as CHANGE_PRIV (change CPU privilege level) —
// a control operation, not a read. The gate resolves the conflict
// safely: 0x21 is NOT in the read set, so it is refused unless the
// operator explicitly allowlists it.

// Message-type byte (mailbox offset 31) values that carry a client
// service request. ACK / ERR types are responses and never gated.
const (
	msgTypeOffset      = 31
	msgTypeShort  byte = 0xC0 // service code at offset 42
	msgTypeExtnd  byte = 0x80 // service code at offset 50

	svcOffsetShort = 42
	svcOffsetExtnd = 50
)

// ServiceCode is a GE-SRTP service-request code (the byte at the
// msg-type-dependent offset). It is the classifier key.
type ServiceCode byte

// Service request codes (Palatis dissector §svc_type). Only the codes
// the classifier needs are named.
//
// SAFETY INVARIANT: the read set holds ONLY pure, non-mutating
// queries. PROG_STORE (0x3f, program upload) does not mutate the PLC
// but exfiltrates the full program, so it is deliberately treated as
// control (refused unless allowlisted), not an auto-pass read.
const (
	// Reads (pure queries).
	SvcShortStatus ServiceCode = 0x00
	SvcGetProgName ServiceCode = 0x03
	SvcReadSysMem  ServiceCode = 0x04
	SvcReadTaskMem ServiceCode = 0x05
	SvcReadProgMem ServiceCode = 0x06
	SvcGetTime     ServiceCode = 0x25
	SvcGetFault    ServiceCode = 0x38
	SvcGetInfo     ServiceCode = 0x43

	// Writes / control.
	SvcWriteSysMem  ServiceCode = 0x07
	SvcWriteTaskMem ServiceCode = 0x08
	SvcWriteProgMem ServiceCode = 0x09
	SvcProgLogon    ServiceCode = 0x20
	SvcChangePriv   ServiceCode = 0x21 // change CPU privilege (see NOTE)
	SvcSetCPUID     ServiceCode = 0x22
	SvcSetPLCRun    ServiceCode = 0x23 // run/stop
	SvcSetPLCTime   ServiceCode = 0x24
	SvcClrFault     ServiceCode = 0x39
	SvcProgStore    ServiceCode = 0x3f // program upload (exfiltration)
	SvcProgLoad     ServiceCode = 0x40 // program download
	SvcToggleForce  ServiceCode = 0x44 // force I/O
)

// Category groups service codes for the proxy allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback; the proxy refuses it.
	CategoryUnknown Category = iota
	// CategoryRead covers pure queries.
	CategoryRead
	// CategoryWrite covers memory writes, program load, run/stop,
	// force, privilege, and program upload.
	CategoryWrite
)

var readServices = map[ServiceCode]struct{}{
	SvcShortStatus: {}, SvcGetProgName: {}, SvcReadSysMem: {},
	SvcReadTaskMem: {}, SvcReadProgMem: {}, SvcGetTime: {},
	SvcGetFault: {}, SvcGetInfo: {},
}

var writeServices = map[ServiceCode]struct{}{
	SvcWriteSysMem: {}, SvcWriteTaskMem: {}, SvcWriteProgMem: {},
	SvcProgLogon: {}, SvcChangePriv: {}, SvcSetCPUID: {},
	SvcSetPLCRun: {}, SvcSetPLCTime: {}, SvcClrFault: {},
	SvcProgStore: {}, SvcProgLoad: {}, SvcToggleForce: {},
}

// Classify returns the Category for a service code. Codes in neither
// table return CategoryUnknown, which the proxy refuses.
func Classify(c ServiceCode) Category {
	if _, ok := readServices[c]; ok {
		return CategoryRead
	}
	if _, ok := writeServices[c]; ok {
		return CategoryWrite
	}
	return CategoryUnknown
}

// ExtractServiceCode recovers the service-request code from a client
// mailbox. It returns (code, true) only for a SHORT or EXTENDED
// request whose service-code byte is present; (0, false) for ACK/ERR
// responses, an unknown message type, or a frame too short to carry
// the code. The proxy treats false as "unverifiable, refuse".
func ExtractServiceCode(mailbox []byte) (ServiceCode, bool) {
	if len(mailbox) <= msgTypeOffset {
		return 0, false
	}
	switch mailbox[msgTypeOffset] {
	case msgTypeShort:
		if len(mailbox) <= svcOffsetShort {
			return 0, false
		}
		return ServiceCode(mailbox[svcOffsetShort]), true
	case msgTypeExtnd:
		if len(mailbox) <= svcOffsetExtnd {
			return 0, false
		}
		return ServiceCode(mailbox[svcOffsetExtnd]), true
	default:
		return 0, false
	}
}

// ReadMailbox reads exactly one 56-byte SRTP mailbox from r. Per the
// Palatis dissector each SRTP PDU is a fixed 56-byte mailbox
// (parse() consumes exactly 56 bytes); a small write's data is inline
// in the mailbox (offsets 48..53). Large multi-packet writes split
// across additional 56-byte mailboxes, which the gate classifies
// per-frame. Returns io.ErrUnexpectedEOF for a truncated mailbox.
func ReadMailbox(r io.Reader) ([]byte, error) {
	buf := make([]byte, MailboxLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
