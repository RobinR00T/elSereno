package wire

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// Validation of link frames travelling toward an outstation, after the
// DNP Users Group Application Note AN2013-004b "Validation of Incoming
// DNP3 Data" (revision b, 13 August 2014), Table 1: the conditions under
// which an outstation's data link layer shall discard a frame. A proxy
// that sits in front of an outstation applies them before it classifies
// a frame, so that it never forwards a frame a conformant outstation
// would discard, and never trusts a field of a frame that fails them.
//
// Until 2026-10-14 neither DNP3 proxy did: both forwarded any frame with
// PRM=0 and the link functions 2 and 9 (the offensive gate also 0),
// together with whatever body they carried, so an application request wrapped in such a frame
// crossed the write-ban (PITF-081).
//
// A header that fails (start octets, LENGTH below 5, header CRC) is
// skipped by ReadFrame, which hunts for the next valid header octet by
// octet, as the note prescribes after a discard.
//
// Rows of Table 1 not applied here, and why:
//   - LENGTH larger than the octets received: the proxies wait for the
//     rest of the frame, as a stream reader must on TCP.
//   - LENGTH larger than the device's maximum frame size: LENGTH is one
//     octet, so a frame is at most 292 octets, which the proxies accept.
//   - PRM clear while no Secondary is expected, a Secondary that is not
//     a permitted response, and an FCB that does not match: these depend
//     on the link state of the session, which the proxies do not track.
//     A Secondary frame that passes CheckToOutstation is header-only, so
//     it carries no application data.
//   - DESTINATION 0xFFFC with self-address disabled, and DESTINATION not
//     the outstation's own address: the proxies do not know the
//     outstation's configuration. The offensive gate's --dnp3-link pins
//     the accepted pairs instead.

// ErrInvalidFrame is wrapped by every Table 1 violation that
// CheckToOutstation reports.
var ErrInvalidFrame = errors.New("dnp3: invalid link frame (AN2013-004b)")

// ErrHeaderCRC is returned by ParseCheckedHeader when the header CRC is
// wrong. The LENGTH field of such a header cannot be trusted, so
// ReadFrame skips it instead of framing a body from it.
var ErrHeaderCRC = errors.New("dnp3: bad header CRC")

// ReadFrame reads the next link frame from r: the parsed header, the
// raw 10-octet header and the on-wire body (BodyLen(h.Length) octets,
// block CRCs included). It hunts for a header whose start octets,
// LENGTH and CRC are valid, dropping one octet at a time until it finds
// one, as AN2013-004b prescribes after a discard: "monitoring of the
// incoming data to locate a new start-of-message (0x05 0x64) shall
// recommence". skipped counts the octets dropped. Only then is LENGTH
// trusted to frame the body. A serial master behind a terminal server
// can deliver line noise inside TCP, so a bad header is skipped, not
// fatal; every frame that comes out still has to pass CheckToOutstation.
func ReadFrame(r *bufio.Reader) (h Header, hdr, body []byte, skipped int, err error) {
	for {
		peek, perr := r.Peek(HeaderLen)
		if perr != nil {
			return Header{}, nil, nil, skipped, perr
		}
		parsed, herr := ParseCheckedHeader(peek)
		if herr != nil {
			_, _ = r.Discard(1)
			skipped++
			continue
		}
		hdr = make([]byte, HeaderLen)
		copy(hdr, peek)
		_, _ = r.Discard(HeaderLen)
		body = make([]byte, BodyLen(parsed.Length))
		if _, rerr := io.ReadFull(r, body); rerr != nil {
			return Header{}, nil, nil, skipped, rerr
		}
		return parsed, hdr, body, skipped, nil
	}
}

// Link function codes as they appear in the control octet, by direction
// (AN2013-004b Figure 1). The primary ones match categories.go.
const (
	SecondaryAck          uint8 = 0
	SecondaryNack         uint8 = 1
	SecondaryLinkStatus   uint8 = 11
	SecondaryNotSupported uint8 = 15
)

// Control octet bits (IEEE 1815 §9.2.4.1.3).
const (
	ctrlPRM = 0x40 // primary message
	ctrlFCB = 0x20 // frame count bit (primary); must be 0 in a secondary
	ctrlFCV = 0x10 // frame count valid (primary); DFC in a secondary
)

// Reserved link address ranges (AN2013-004b Table 1, Technical Bulletin
// 2013-002, IEEE 1815 §9.2.5.2.3).
const (
	reservedDestFirst uint16 = 0xFFF0
	reservedDestLast  uint16 = 0xFFFB
	reservedSrcFirst  uint16 = 0xFFF0
)

// ParseCheckedHeader parses the 10-octet header and verifies its CRC.
func ParseCheckedHeader(b []byte) (Header, error) {
	h, err := ParseHeader(b)
	if err != nil {
		return Header{}, err
	}
	if CRC16(b[0:8]) != h.CRC {
		return Header{}, ErrHeaderCRC
	}
	return h, nil
}

// IsUserData reports whether a control octet is a primary frame that
// carries user data (CONFIRMED_USER_DATA or UNCONFIRMED_USER_DATA).
// Only these frames may carry octets after the header.
func IsUserData(ctrl uint8) bool {
	fc := ctrl & 0x0F
	return ctrl&ctrlPRM != 0 && (fc == PrimaryConfirmedData || fc == PrimaryUnconfirmedData)
}

// validControl reports whether the combination of PRM, FCV and function
// code is a valid one in IEEE 1815-2012 (AN2013-004b Figure 1). Reset of
// User Process (primary 1) is not: the 2012 edition removed it.
func validControl(ctrl uint8) bool {
	fc := ctrl & 0x0F
	if ctrl&ctrlPRM == 0 {
		if ctrl&ctrlFCB != 0 {
			return false
		}
		switch fc {
		case SecondaryAck, SecondaryNack, SecondaryLinkStatus, SecondaryNotSupported:
			return true
		}
		return false
	}
	fcv := ctrl&ctrlFCV != 0
	switch fc {
	case PrimaryTestLinkStates, PrimaryConfirmedData:
		return fcv
	case PrimaryResetLinkStates, PrimaryUnconfirmedData, PrimaryRequestLinkState:
		return !fcv
	}
	return false
}

// CheckToOutstation applies the stateless rows of AN2013-004b Table 1 to
// a frame travelling toward an outstation whose header h already passed
// ParseCheckedHeader. wireBody is what follows the header on the wire
// (BodyLen(h.Length) octets). On success it returns the user data with
// the block CRCs removed (nil for a header-only frame). Every error wraps
// ErrInvalidFrame; the frame is to be discarded, not answered.
func CheckToOutstation(h Header, wireBody []byte) ([]byte, error) {
	if !validControl(h.Control) {
		return nil, fmt.Errorf("%w: control 0x%02x is not a valid PRM/FCV/function combination", ErrInvalidFrame, h.Control)
	}
	userData := IsUserData(h.Control)
	if userData && h.Length < 6 {
		return nil, fmt.Errorf("%w: user-data frame with length %d carries no data", ErrInvalidFrame, h.Length)
	}
	if !userData && h.Length != 5 {
		return nil, fmt.Errorf("%w: control 0x%02x carries data (length %d, want 5)", ErrInvalidFrame, h.Control, h.Length)
	}
	if h.Dest >= reservedDestFirst && h.Dest <= reservedDestLast {
		return nil, fmt.Errorf("%w: reserved destination 0x%04x", ErrInvalidFrame, h.Dest)
	}
	if IsBroadcast(h.Dest) && !userData {
		return nil, fmt.Errorf("%w: control 0x%02x to broadcast address 0x%04x", ErrInvalidFrame, h.Control, h.Dest)
	}
	if h.Src >= reservedSrcFirst {
		return nil, fmt.Errorf("%w: reserved source 0x%04x", ErrInvalidFrame, h.Src)
	}
	if !userData {
		return nil, nil
	}
	data, ok := StripBlockCRCs(wireBody, int(h.Length)-5)
	if !ok {
		return nil, fmt.Errorf("%w: bad block CRC", ErrInvalidFrame)
	}
	return data, nil
}
