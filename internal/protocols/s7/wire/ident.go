package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// S7 UserData Read SZL identity lists for the CPU identity/firmware probe.
// SZL 0x0011 (Module Identification) carries the module order number
// (MLFB) and firmware version; SZL 0x001C (Component Identification)
// carries the module type name, serial number, plant designation and
// station name. Together they pin the exact CPU + firmware, which is what
// a CVE / advisory lookup needs. Read-only recon.
//
// Field order/values are validated byte for byte against a real captured
// session (see ident_test.go, ITI/ICS-Security-Tools
// s7comm_reading_plc_status.pcap) + the Wireshark S7comm dissector.

// SZL-IDs for the identity lists.
const (
	SZLIDModuleIdent    uint16 = 0x0011
	SZLIDComponentIdent uint16 = 0x001C
)

// SZL 0x0011 record indices (Module Identification).
const (
	ModuleIndexOrderNumber uint16 = 1 // MLFB of the module + hardware version
	ModuleIndexBasicHW     uint16 = 6 // basic hardware order number
	ModuleIndexFirmware    uint16 = 7 // basic firmware version
)

// SZL 0x001C record indices (Component Identification), Wireshark s7comm.
const (
	ComponentIndexStationName uint16 = 1
	ComponentIndexModuleName  uint16 = 2
	ComponentIndexPlantDesig  uint16 = 3
	ComponentIndexCopyright   uint16 = 4
	ComponentIndexSerial      uint16 = 5
	ComponentIndexModuleType  uint16 = 7
	ComponentIndexLocation    uint16 = 8
)

// maxSZLRecords caps the record count a Read SZL response may claim, so a
// hostile PLC cannot drive a huge allocation from the count field.
const maxSZLRecords = 1024

// ParseSZLRecords validates that pdu is a positive S7 UserData Read SZL
// response for wantSZLID and returns its fixed-length records (each
// starting with the 2-byte record index). ok=false when it is not a
// well-formed positive Read SZL response for that SZL. Fail-closed on
// truncation or an over-large record count.
func ParseSZLRecords(pdu []byte, wantSZLID uint16) (records [][]byte, ok bool) {
	if len(pdu) < s7HeaderMin || pdu[0] != 0x32 || pdu[1] != ROSCTRUserData {
		return nil, false
	}
	paramLen := int(binary.BigEndian.Uint16(pdu[6:8]))
	dataOff := s7HeaderMin + paramLen
	if dataOff > len(pdu) {
		return nil, false
	}
	data := pdu[dataOff:]
	if len(data) < 4 || data[0] != 0xFF {
		return nil, false // no data / SZL unavailable
	}
	szl := data[4:]
	if len(szl) < szlBlockHeaderLen {
		return nil, false
	}
	if binary.BigEndian.Uint16(szl[0:2]) != wantSZLID {
		return nil, false
	}
	recLen := int(binary.BigEndian.Uint16(szl[4:6]))
	recN := int(binary.BigEndian.Uint16(szl[6:8]))
	if recLen < 2 || recN < 1 || recN > maxSZLRecords {
		return nil, false
	}
	// A CPU can return more records than fit in one PDU (the rest follow
	// in continuation PDUs); the block-header count is the TOTAL, not what
	// this PDU carries. Parse only the complete records present here, up to
	// the claimed count. The first PDU already holds the identity fields
	// the probe needs.
	body := szl[szlBlockHeaderLen:]
	n := len(body) / recLen
	if n > recN {
		n = recN
	}
	if n < 1 {
		return nil, false
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, body[i*recLen:(i+1)*recLen])
	}
	return out, true
}

// IdentRecord is one SZL 0x001C component-identification string.
type IdentRecord struct {
	Index uint16
	Text  string
}

// ParseComponentIdent walks an SZL 0x001C response PDU (starting at 0x32)
// and returns its identification strings. ok=false when it is not a
// well-formed 0x001C response.
func ParseComponentIdent(pdu []byte) ([]IdentRecord, bool) {
	recs, ok := ParseSZLRecords(pdu, SZLIDComponentIdent)
	if !ok {
		return nil, false
	}
	out := make([]IdentRecord, 0, len(recs))
	for _, r := range recs {
		if len(r) < 2 {
			continue
		}
		out = append(out, IdentRecord{
			Index: binary.BigEndian.Uint16(r[0:2]),
			Text:  trimSZLString(r[2:]),
		})
	}
	return out, true
}

// ModuleIdentRecord is one SZL 0x0011 module-identification record: the
// order number (MLFB) and, for a firmware record, the decoded version.
type ModuleIdentRecord struct {
	Index   uint16
	MLFB    string
	Version string // "Vx.y.z" for a firmware record, else ""
}

// moduleIdentRecordLen is index(2)+MLFB(20)+bgtyp(2)+ausbg1(2)+ausbg2(2).
const moduleIdentRecordLen = 28

// ParseModuleIdent walks an SZL 0x0011 response PDU (starting at 0x32) and
// returns its module-identification records. ok=false when it is not a
// well-formed 0x0011 response.
func ParseModuleIdent(pdu []byte) ([]ModuleIdentRecord, bool) {
	recs, ok := ParseSZLRecords(pdu, SZLIDModuleIdent)
	if !ok {
		return nil, false
	}
	out := make([]ModuleIdentRecord, 0, len(recs))
	for _, r := range recs {
		if len(r) < moduleIdentRecordLen {
			continue
		}
		out = append(out, ModuleIdentRecord{
			Index:   binary.BigEndian.Uint16(r[0:2]),
			MLFB:    trimSZLString(r[2:22]),
			Version: decodeModuleVersion(r[24:28]),
		})
	}
	return out, true
}

// decodeModuleVersion decodes the 4 version bytes (ausbg1, ausbg2) of an
// SZL 0x0011 record. A firmware record carries a 'V' marker (0x56) in the
// first byte, followed by major/minor/patch: e.g. 56 03 02 06 -> "V3.2.6".
// Records without the marker (hardware functional state) return "".
func decodeModuleVersion(b []byte) string {
	if len(b) < 4 || b[0] != 'V' {
		return ""
	}
	return fmt.Sprintf("V%d.%d.%d", b[1], b[2], b[3])
}

// trimSZLString renders a fixed-width, space/NUL-padded SZL field as a
// clean string: it stops at the first NUL and keeps only printable ASCII,
// so hostile control bytes can't reach a terminal.
func trimSZLString(b []byte) string {
	if i := bytes.IndexByte(b, 0x00); i >= 0 {
		b = b[:i]
	}
	s := strings.Map(func(r rune) rune {
		if r >= 0x20 && r < 0x7f {
			return r
		}
		return -1
	}, string(b))
	return strings.TrimSpace(s)
}
