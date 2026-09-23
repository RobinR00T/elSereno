package goose

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EtherType values for the IEC 61850 substation-bus protocols.
const (
	EtherTypeGOOSE uint16 = 0x88B8 // IEC 61850-8-1 GOOSE
	EtherTypeSV    uint16 = 0x88BA // IEC 61850-9-2 Sampled Values
	etherTypeVLAN  uint16 = 0x8100 // 802.1Q tag (GOOSE/SV are usually VLAN-tagged)
)

// Kind tags a dissected frame by protocol.
type Kind string

// Frame kinds.
const (
	KindGOOSE Kind = "goose"
	KindSV    Kind = "sv"
)

var (
	// ErrTooShort means the frame ended before a required field.
	ErrTooShort = errors.New("goose: frame too short")
	// ErrNotSubstation means the EtherType is neither GOOSE nor SV.
	ErrNotSubstation = errors.New("goose: not a GOOSE/SV EtherType")
	// ErrBadAPDU means the application PDU tag/length did not parse.
	ErrBadAPDU = errors.New("goose: malformed APDU")
)

// PDU is the subset of the GOOSE IECGoosePdu the monitor needs. Fields
// absent from the frame keep their zero value; Present* flags mark the
// boolean fields so "false" is distinguishable from "not sent".
type PDU struct {
	APPID             uint16
	GocbRef           string  // gocbRef       [0] VisibleString
	TimeAllowedToLive uint32  // timeAllowedtoLive [1] INTEGER (ms)
	DatSet            string  // datSet        [2] VisibleString
	GoID              string  // goID          [3] VisibleString
	Timestamp         [8]byte // t            [4] UtcTime (raw 8 bytes)
	StNum             uint32  // stNum         [5] INTEGER
	SqNum             uint32  // sqNum         [6] INTEGER
	Test              bool    // simulation    [7] BOOLEAN
	TestPresent       bool
	ConfRev           uint32 // confRev       [8] INTEGER
	NdsCom            bool   // ndsCom        [9] BOOLEAN
	NdsComPresent     bool
	NumDatSetEntries  uint32 // numDatSetEntries [10] INTEGER
}

// SVPDU is the subset of the SV savPdu the monitor needs. SV carries one
// or more ASDUs; the first ASDU's identity fields are surfaced (the
// common single-ASDU case).
type SVPDU struct {
	APPID    uint16
	NoASDU   uint32 // noASDU  [0] INTEGER
	SvID     string // svID    [0] VisibleString (inside the ASDU)
	SmpCnt   uint32 // smpCnt  [2] INTEGER
	ConfRev  uint32 // confRev [3] INTEGER
	SmpSynch uint32 // smpSynch [5] INTEGER (present when signalled)
}

// Frame is a dissected GOOSE or SV frame.
type Frame struct {
	Kind   Kind
	VLAN   bool
	VLANID uint16 // 12-bit VLAN id when VLAN is true
	Goose  *PDU
	SV     *SVPDU
}

// stripEthernet returns the EtherType and the payload after the Ethernet
// (and optional 802.1Q) header. It does not validate the MAC addresses.
func stripEthernet(frame []byte) (etherType uint16, vlan bool, vlanID uint16, payload []byte, err error) {
	if len(frame) < 14 {
		return 0, false, 0, nil, ErrTooShort
	}
	et := binary.BigEndian.Uint16(frame[12:14])
	if et == etherTypeVLAN {
		if len(frame) < 18 {
			return 0, false, 0, nil, ErrTooShort
		}
		tci := binary.BigEndian.Uint16(frame[14:16])
		et = binary.BigEndian.Uint16(frame[16:18])
		return et, true, tci & 0x0FFF, frame[18:], nil
	}
	return et, false, 0, frame[14:], nil
}

// gooseHeaderLen is the fixed reserved header ahead of the APDU:
// APPID(2) + Length(2) + Reserved1(2) + Reserved2(2).
const gooseHeaderLen = 8

// Dissect parses one Ethernet frame carrying GOOSE or SV. Returns
// ErrNotSubstation when the EtherType is something else, so a caller can
// filter a mixed capture cheaply.
func Dissect(frame []byte) (*Frame, error) {
	et, vlan, vlanID, payload, err := stripEthernet(frame)
	if err != nil {
		return nil, err
	}
	if et != EtherTypeGOOSE && et != EtherTypeSV {
		return nil, ErrNotSubstation
	}
	if len(payload) < gooseHeaderLen {
		return nil, ErrTooShort
	}
	appID := binary.BigEndian.Uint16(payload[0:2])
	length := int(binary.BigEndian.Uint16(payload[2:4]))
	// Length counts from APPID to the end of the PDU. Clamp to the
	// available bytes: real capture tails (FCS, padding) may extend
	// past it, and a hostile Length must never drive an over-read.
	if length < gooseHeaderLen || length > len(payload) {
		length = len(payload)
	}
	apdu := payload[gooseHeaderLen:length]

	f := &Frame{VLAN: vlan, VLANID: vlanID}
	switch et {
	case EtherTypeGOOSE:
		pdu, err := parseGoosePDU(apdu)
		if err != nil {
			return nil, err
		}
		pdu.APPID = appID
		f.Kind = KindGOOSE
		f.Goose = pdu
	case EtherTypeSV:
		pdu, err := parseSVPDU(apdu)
		if err != nil {
			return nil, err
		}
		pdu.APPID = appID
		f.Kind = KindSV
		f.SV = pdu
	}
	return f, nil
}

// ---- BER (DER) minimal reader ---------------------------------------

// berTLV is one parsed tag-length-value element.
type berTLV struct {
	tag   byte
	value []byte
}

// readTLV decodes one BER element at the front of b. Supports the short
// form and the long definite length form (0x8N). Returns the element and
// the total bytes consumed (tag + length octets + value).
func readTLV(b []byte) (berTLV, int, bool) {
	if len(b) < 2 {
		return berTLV{}, 0, false
	}
	tag := b[0]
	off := 1
	l := int(b[off])
	off++
	if l&0x80 != 0 {
		n := l & 0x7F
		// A length-of-length beyond 4 octets is not real GOOSE/SV; guard
		// against a huge shift and an implausible length.
		if n == 0 || n > 4 || off+n > len(b) {
			return berTLV{}, 0, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[off])
			off++
		}
	}
	if l < 0 || off+l > len(b) {
		return berTLV{}, 0, false
	}
	return berTLV{tag: tag, value: b[off : off+l]}, off + l, true
}

// berUint reads a BER INTEGER value as an unsigned integer, capped at 32
// bits. GOOSE stNum / sqNum / confRev are all small unsigned counters.
func berUint(v []byte) uint32 {
	var n uint64
	for _, c := range v {
		n = n<<8 | uint64(c)
		if n > 0xFFFFFFFF {
			return 0xFFFFFFFF
		}
	}
	return uint32(n)
}

// berBool reads a BER BOOLEAN (any non-zero octet is true).
func berBool(v []byte) bool {
	for _, c := range v {
		if c != 0 {
			return true
		}
	}
	return false
}

// GOOSE IECGoosePdu context tags (IEC 61850-8-1 §A.3).
const (
	tagGooseAPDU  byte = 0x61 // [APPLICATION 1] IECGoosePdu (constructed)
	tagGocbRef    byte = 0x80
	tagTimeToLive byte = 0x81
	tagDatSet     byte = 0x82
	tagGoID       byte = 0x83
	tagTimestamp  byte = 0x84
	tagStNum      byte = 0x85
	tagSqNum      byte = 0x86
	tagSimulation byte = 0x87
	tagConfRev    byte = 0x88
	tagNdsCom     byte = 0x89
	tagNumDatSet  byte = 0x8A
	tagAllData    byte = 0xAB
)

// parseGoosePDU decodes the IECGoosePdu APDU (starting at the 0x61 tag).
func parseGoosePDU(apdu []byte) (*PDU, error) {
	top, _, ok := readTLV(apdu)
	if !ok || top.tag != tagGooseAPDU {
		return nil, ErrBadAPDU
	}
	pdu := &PDU{}
	body := top.value
	for len(body) > 0 {
		el, n, ok := readTLV(body)
		if !ok {
			return nil, ErrBadAPDU
		}
		applyGooseField(pdu, el)
		body = body[n:]
	}
	return pdu, nil
}

// applyGooseField writes one decoded element into the PDU. Split from
// parseGoosePDU to keep the loop under the cyclomatic-complexity budget.
func applyGooseField(pdu *PDU, el berTLV) {
	switch el.tag {
	case tagGocbRef:
		pdu.GocbRef = string(el.value)
	case tagTimeToLive:
		pdu.TimeAllowedToLive = berUint(el.value)
	case tagDatSet:
		pdu.DatSet = string(el.value)
	case tagGoID:
		pdu.GoID = string(el.value)
	case tagTimestamp:
		copy(pdu.Timestamp[:], el.value)
	case tagStNum:
		pdu.StNum = berUint(el.value)
	case tagSqNum:
		pdu.SqNum = berUint(el.value)
	case tagSimulation:
		pdu.Test = berBool(el.value)
		pdu.TestPresent = true
	case tagConfRev:
		pdu.ConfRev = berUint(el.value)
	case tagNdsCom:
		pdu.NdsCom = berBool(el.value)
		pdu.NdsComPresent = true
	case tagNumDatSet:
		pdu.NumDatSetEntries = berUint(el.value)
	case tagAllData:
		// Dataset payload; not needed for identity/anomaly monitoring.
	}
}

// SV savPdu tags (IEC 61850-9-2).
const (
	tagSVSavPdu   byte = 0x60 // [APPLICATION 0] savPdu (constructed)
	tagSVNoASDU   byte = 0x80 // noASDU  [0] INTEGER
	tagSVSeqASDU  byte = 0xA2 // seqOfASDU [2] (constructed) of ASDU
	tagSVASDU     byte = 0x30 // ASDU SEQUENCE
	tagSVID       byte = 0x80 // svID    [0] VisibleString (inside ASDU)
	tagSVSmpCnt   byte = 0x82 // smpCnt  [2] INTEGER (OCTET STRING of 2)
	tagSVConfRev  byte = 0x83 // confRev [3] INTEGER
	tagSVSmpSynch byte = 0x85 // smpSynch [5] INTEGER/BOOLEAN
)

// parseSVPDU decodes the savPdu APDU (starting at the 0x60 tag) and
// surfaces the first ASDU's identity fields.
func parseSVPDU(apdu []byte) (*SVPDU, error) {
	top, _, ok := readTLV(apdu)
	if !ok || top.tag != tagSVSavPdu {
		return nil, ErrBadAPDU
	}
	pdu := &SVPDU{}
	body := top.value
	for len(body) > 0 {
		el, n, ok := readTLV(body)
		if !ok {
			return nil, ErrBadAPDU
		}
		switch el.tag {
		case tagSVNoASDU:
			pdu.NoASDU = berUint(el.value)
		case tagSVSeqASDU:
			applyFirstASDU(pdu, el.value)
		}
		body = body[n:]
	}
	return pdu, nil
}

// applyFirstASDU decodes the identity fields of the first ASDU inside
// the seqOfASDU element.
func applyFirstASDU(pdu *SVPDU, seq []byte) {
	asdu, _, ok := readTLV(seq)
	if !ok || asdu.tag != tagSVASDU {
		return
	}
	body := asdu.value
	for len(body) > 0 {
		el, n, ok := readTLV(body)
		if !ok {
			return
		}
		switch el.tag {
		case tagSVID:
			pdu.SvID = string(el.value)
		case tagSVSmpCnt:
			pdu.SmpCnt = berUint(el.value)
		case tagSVConfRev:
			pdu.ConfRev = berUint(el.value)
		case tagSVSmpSynch:
			pdu.SmpSynch = berUint(el.value)
		}
		body = body[n:]
	}
}

// String renders a one-line identity summary for the CLI.
func (f *Frame) String() string {
	switch f.Kind {
	case KindGOOSE:
		g := f.Goose
		return fmt.Sprintf("GOOSE appid=0x%04x goID=%q gocbRef=%q stNum=%d sqNum=%d test=%t confRev=%d ttl=%dms",
			g.APPID, g.GoID, g.GocbRef, g.StNum, g.SqNum, g.Test, g.ConfRev, g.TimeAllowedToLive)
	case KindSV:
		s := f.SV
		return fmt.Sprintf("SV appid=0x%04x svID=%q smpCnt=%d confRev=%d noASDU=%d",
			s.APPID, s.SvID, s.SmpCnt, s.ConfRev, s.NoASDU)
	}
	return "unknown"
}
