package wire

import (
	"encoding/binary"
	"hash/crc32"
)

// Channel-open (opt-in active fingerprint).
//
// A bare Block Driver magic does not elicit a reply (see BuildHello /
// PITF-068): a CODESYS V3 gateway only answers a well-formed PDU. This
// file builds the minimal host-independent "open a channel" PDU that
// the gateway replies to, so the `codesys-active` opt-in plugin can
// confirm a gateway by its Block-Driver-framed response rather than
// relying on a plaintext banner.
//
// It is a READ-ONLY DETECTION handshake: it opens a channel to read the
// gateway's reply, and issues no service request that reads, writes, or
// changes controller state. The frame is ported byte for byte from the
// Tenable CODESYS gateway V3 PoC (codesys_gateway_v3_config_modification_
// tra_2020_04.py): block driver (magic + length) wrapping a datagram
// (L3, service 64) wrapping a channel-open meta request (L4, type 3)
// wrapping {clientId, maxBlockSize 0x1f4000, 0x08}. The only varying
// field is the client-chosen channel id; all addressing is zero
// (host-independent), so the frame generalises across gateways.
//
// VALIDATION: the construction is validated byte for byte against the
// Tenable reference (channel_test.go, fixed client id). It has NOT been
// exercised against a live 1217 gateway, so the response path reuses the
// existing, capture-confirmed Block Driver magic recognition (Classify /
// IsBlockDriverFrame) rather than asserting a specific reply shape.

const (
	// chanOpenMaxBlockSize is the max-block-size field the Tenable PoC
	// sends in the channel-open datagram (0x1f4000).
	chanOpenMaxBlockSize uint32 = 0x1f4000
	// chanOpenTrailer is the fixed 4-byte trailer after the max-block
	// size in the channel-open data (0x00000008).
	chanOpenTrailer uint32 = 0x00000008

	// l3ServiceDatagram is the L3 service id for a datagram (64).
	l3ServiceDatagram byte = 64
	// l4TypeChannelOpen is the L4 meta-request type for channel open (3).
	l4TypeChannelOpen byte = 3
)

// BuildChannelOpen returns the host-independent CODESYS V3 channel-open
// PDU for the given client-chosen channel id. See the file comment: a
// read-only detection handshake, ported byte for byte from the Tenable
// reference. The client id is the only caller-varied field; everything
// else (zero addressing) is fixed, so the frame works against any
// gateway.
func BuildChannelOpen(clientID uint32) []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], clientID)
	binary.LittleEndian.PutUint32(data[4:8], chanOpenMaxBlockSize)
	binary.LittleEndian.PutUint32(data[8:12], chanOpenTrailer)
	return blockDriverWrap(layer3(l3ServiceDatagram, layer4Meta(l4TypeChannelOpen, data)))
}

// layer4Meta builds a CODESYS L4 meta request: type|0xC0, 0, 0x0101,
// then a CRC32 (IEEE) over the header + 4 zero bytes + data, then data.
func layer4Meta(typ byte, data []byte) []byte {
	hdr := []byte{typ | 0xC0, 0x00, 0x01, 0x01}
	crcIn := make([]byte, 0, len(hdr)+4+len(data))
	crcIn = append(crcIn, hdr...)
	crcIn = append(crcIn, 0, 0, 0, 0)
	crcIn = append(crcIn, data...)
	out := make([]byte, 0, len(hdr)+4+len(data))
	out = append(out, hdr...)
	out = binary.LittleEndian.AppendUint32(out, crc32.ChecksumIEEE(crcIn))
	out = append(out, data...)
	return out
}

// layer3 builds a CODESYS L3 datagram header with all-zero sender /
// receiver addressing (host-independent), then the payload. The fixed
// header bytes (0xc5, hop/offset, priority, service, msg id, addr-len)
// are from the Tenable reference's layer3(service, data) with its
// defaults (sender 8 bytes, receiver 6 bytes, both zero).
func layer3(service byte, data []byte) []byte {
	const (
		hopCount    = 13
		offsetWords = 3
		priority    = 1
		senderLen   = 8
		receiverLen = 6
	)
	slrl := byte(((senderLen/2)<<4)&0xf0 | ((receiverLen / 2) & 0x0f))
	b2 := byte(((hopCount << 3) & 0xf8) | (offsetWords & 0x07))
	b3 := byte((priority << 6) & 0xc0)
	out := make([]byte, 0, 6+receiverLen+senderLen+len(data))
	out = append(out, 0xc5, b2, b3, service, 0x00, slrl)
	out = append(out, make([]byte, receiverLen)...)
	out = append(out, make([]byte, senderLen)...)
	// 6 + 6 + 8 = 20 bytes, already a multiple of 4, so no padding.
	out = append(out, data...)
	return out
}

// blockDriverWrap prepends the 8-byte Block Driver header (magic +
// little-endian total length, which includes the 8-byte header).
func blockDriverWrap(data []byte) []byte {
	out := make([]byte, 0, BlockDriverMagicLen+4+len(data))
	out = append(out, BlockDriverMagic...)
	// #nosec G115 -- frame length is bounded well below uint32 max.
	out = binary.LittleEndian.AppendUint32(out, uint32(len(data)+8))
	out = append(out, data...)
	return out
}
