package wire

// DNP3 data-link CRC and block framing (IEEE 1815 §9.2.4.4).
//
// The user data that follows the 10-byte header is transmitted in
// blocks of up to 16 octets, each block followed by its own 2-octet
// CRC (little-endian). The Length field counts only the control,
// destination, source and user-data octets: it excludes every CRC and
// the two start octets. So the number of octets actually on the wire
// after the header is the user-data length plus two CRC octets per
// started block.

// CRC16 computes the DNP3 CRC-16: polynomial 0x3D65, reflected input
// and output, init 0x0000, final XOR 0xFFFF. The bit-at-a-time form
// uses the reflected polynomial 0xA6BC. The catalogued check value for
// the ASCII string "123456789" is 0xEA82 (CRC-16/DNP).
func CRC16(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xA6BC
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFF
}

// blockCRCBytes returns the number of CRC octets a user-data payload of
// userDataLen octets carries on the wire (two per started 16-octet
// block).
func blockCRCBytes(userDataLen int) int {
	if userDataLen <= 0 {
		return 0
	}
	return 2 * ((userDataLen + 15) / 16)
}

// BodyLen returns how many octets follow the 10-byte header on the
// wire for a frame whose Length field is `length`: the user data plus
// its per-block CRCs.
func BodyLen(length uint8) int {
	ud := int(length) - 5
	if ud < 0 {
		ud = 0
	}
	return ud + blockCRCBytes(ud)
}

// AppendBlockCRCs splits userData into <=16-octet blocks and returns
// the on-wire body: each block followed by its little-endian CRC.
func AppendBlockCRCs(userData []byte) []byte {
	out := make([]byte, 0, len(userData)+blockCRCBytes(len(userData)))
	for i := 0; i < len(userData); i += 16 {
		end := i + 16
		if end > len(userData) {
			end = len(userData)
		}
		block := userData[i:end]
		out = append(out, block...)
		crc := CRC16(block)
		out = append(out, byte(crc&0xFF), byte(crc>>8))
	}
	return out
}

// StripBlockCRCs removes the per-block CRCs from an on-wire body and
// returns the clean user data. It verifies every block CRC and returns
// ok=false on any length mismatch or CRC error: a corrupt or malformed
// frame fails closed rather than being inspected on wrong boundaries.
func StripBlockCRCs(wireBody []byte, userDataLen int) (userData []byte, ok bool) {
	if userDataLen < 0 || len(wireBody) != userDataLen+blockCRCBytes(userDataLen) {
		return nil, false
	}
	out := make([]byte, 0, userDataLen)
	pos := 0
	remaining := userDataLen
	for remaining > 0 {
		n := 16
		if remaining < 16 {
			n = remaining
		}
		block := wireBody[pos : pos+n]
		got := uint16(wireBody[pos+n]) | uint16(wireBody[pos+n+1])<<8
		if CRC16(block) != got {
			return nil, false
		}
		out = append(out, block...)
		pos += n + 2
		remaining -= n
	}
	return out, true
}
