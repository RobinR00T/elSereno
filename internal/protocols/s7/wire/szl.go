package wire

import "encoding/binary"

// S7 UserData Read SZL (System Status List) for the CPU protection-level
// probe. Reading SZL-ID 0x0132 index 4 returns the CPU's protection
// configuration: the effective (real) protection level and the mode
// selector position, which together say whether a stranger can write or
// control the PLC without a password. Read-only recon.
//
// Field order/values are validated byte for byte against a real captured
// session (see szl_test.go, ITI/ICS-Security-Tools
// s7comm_reading_plc_status.pcap) + the Wireshark S7comm dissector
// (packet-s7comm_szl_ids.c).

// SZL-ID + index for the CPU protection record (Part: SFC51 RDSYSST).
const (
	SZLIDProtection    uint16 = 0x0132
	SZLIndexProtection uint16 = 0x0004
)

// Mode selector (bart_sch) values, Wireshark s7comm.
const (
	ModeSelectorRUN  uint16 = 1
	ModeSelectorRUNP uint16 = 2
	ModeSelectorSTOP uint16 = 3
	ModeSelectorMRES uint16 = 4
)

// BuildReadSZLRequest returns the COTP+S7 payload (the bytes after the
// TPKT header, ready for WriteTPKT) for an S7 UserData Read SZL request
// (CPU-functions group 0x04, Read SZL subfunction 0x01). pduRef
// correlates the response.
func BuildReadSZLRequest(pduRef, szlID, szlIndex uint16) []byte {
	param := []byte{
		0x00, 0x01, 0x12, // parameter head (constant)
		0x04, // parameter length (4 bytes follow)
		0x11, // method: request
		0x44, // type (request, high nibble 4) | function group (CPU functions, low nibble 4)
		0x01, // subfunction: Read SZL
		0x00, // sequence number
	}
	data := make([]byte, 8)
	data[0] = 0xFF                           // return code: data follows
	data[1] = 0x09                           // transport size: octet string
	binary.BigEndian.PutUint16(data[2:4], 4) // user-data length: SZL-ID + index
	binary.BigEndian.PutUint16(data[4:6], szlID)
	binary.BigEndian.PutUint16(data[6:8], szlIndex)

	out := make([]byte, 0, len(cotpDataHeader)+s7HeaderMin+len(param)+len(data))
	out = append(out, cotpDataHeader...)
	out = append(out, buildS7Header(ROSCTRUserData, pduRef, uint16(len(param)), uint16(len(data)))...) // #nosec G115 -- param/data lengths are fixed small constants
	out = append(out, param...)
	out = append(out, data...)
	return out
}

// ProtectionRecord holds the fields of SZL 0x0132 index 4 (CPU
// protection) that decide exposure. Each is 0 when the CPU leaves it
// undefined.
type ProtectionRecord struct {
	// KeySwitchLevel is the protection level set with the mode-selector
	// key switch (0=undefined, 1/2/3).
	KeySwitchLevel uint16 `json:"key_switch_level"`
	// ParamLevel is the parameter-assigned protection level from the
	// hardware configuration (0=none/undefined, 1/2/3).
	ParamLevel uint16 `json:"param_level"`
	// RealLevel is the CPU's effective protection level (1/2/3): the one
	// that actually governs access. The headline field.
	RealLevel uint16 `json:"real_level"`
	// ModeSelector is the key-switch position (bart_sch): 1=RUN, 2=RUN_P,
	// 3=STOP, 4=MRES; 0=undefined / no physical switch.
	ModeSelector uint16 `json:"mode_selector"`
}

// szlBlockHeaderLen is SZL-ID(2)+index(2)+partial-list-length(2)+count(2).
const szlBlockHeaderLen = 8

// protectionRecordMinLen is the words the probe reads: index, key,
// param, real, bart_sch (5 words = 10 bytes). Real records are longer
// (the capture's is 40 bytes) with trailing reserved fields.
const protectionRecordMinLen = 10

// ParseProtectionSZL walks an S7 UserData Read SZL response PDU (starting
// at the 0x32 protocol id) for SZL-ID 0x0132 index 4 and returns the
// protection record. ok=false when it is not a well-formed positive Read
// SZL response for that SZL, or carries no record (an empty or error
// response is a separate signal the caller handles).
func ParseProtectionSZL(pdu []byte) (ProtectionRecord, bool) {
	var rec ProtectionRecord
	if len(pdu) < s7HeaderMin || pdu[0] != 0x32 || pdu[1] != ROSCTRUserData {
		return rec, false
	}
	paramLen := int(binary.BigEndian.Uint16(pdu[6:8]))
	dataOff := s7HeaderMin + paramLen
	if dataOff > len(pdu) {
		return rec, false
	}
	data := pdu[dataOff:]
	// Data area: return code(1) + transport size(1) + length(2) + SZL block.
	if len(data) < 4 || data[0] != 0xFF {
		return rec, false // no data / SZL unavailable (protected or unsupported)
	}
	szl := data[4:]
	if len(szl) < szlBlockHeaderLen {
		return rec, false
	}
	szlID := binary.BigEndian.Uint16(szl[0:2])
	szlIndex := binary.BigEndian.Uint16(szl[2:4])
	recLen := int(binary.BigEndian.Uint16(szl[4:6]))
	recN := int(binary.BigEndian.Uint16(szl[6:8]))
	if szlID != SZLIDProtection || szlIndex != SZLIndexProtection {
		return rec, false
	}
	if recN < 1 || recLen < protectionRecordMinLen {
		return rec, false
	}
	body := szl[szlBlockHeaderLen:]
	if len(body) < recLen {
		return rec, false
	}
	r := body[:recLen]
	// Record words: [0]index [1]key [2]param [3]real [4]bart_sch ...
	rec.KeySwitchLevel = binary.BigEndian.Uint16(r[2:4])
	rec.ParamLevel = binary.BigEndian.Uint16(r[4:6])
	rec.RealLevel = binary.BigEndian.Uint16(r[6:8])
	rec.ModeSelector = binary.BigEndian.Uint16(r[8:10])
	return rec, true
}
