package profinet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// DCP frame constants.
const (
	// EtherTypePROFINET is the IEEE-registered ethertype for
	// PROFINET RT frames (DCP, RTC, RTA, etc).
	EtherTypePROFINET uint16 = 0x8892

	// MulticastIdentify is the dst MAC for DCP Identify
	// requests — all PROFINET devices on the segment listen.
	MulticastIdentify = "01:0e:cf:00:00:00"

	// FrameIDIdentifyRequest is the DCP frame ID for a unicast
	// or multicast Identify request.
	FrameIDIdentifyRequest uint16 = 0xFEFE
	// FrameIDIdentifyResponse — devices' replies.
	FrameIDIdentifyResponse uint16 = 0xFEFF
	// FrameIDHello — DCP Hello (used during boot announcement).
	FrameIDHello uint16 = 0xFEFC
)

// Service IDs.
const (
	ServiceGet      = 0x04
	ServiceSet      = 0x03
	ServiceIdentify = 0x05
	ServiceHello    = 0x06
)

// Service types.
const (
	ServiceTypeRequest  = 0x00
	ServiceTypeResponse = 0x01
)

// Option codes.
const (
	OptionIP      = 0x01
	OptionDevice  = 0x02
	OptionDHCP    = 0x03
	OptionControl = 0x05
	OptionAll     = 0xFF
)

// Suboption codes for OptionDevice.
const (
	SubDeviceManufacturerSpecific = 0x01
	SubDeviceNameOfStation        = 0x02
	SubDeviceID                   = 0x03
	SubDeviceRole                 = 0x04
	SubDeviceOptions              = 0x05
	SubDeviceAliasName            = 0x06
	SubDeviceInstance             = 0x07
	SubDeviceOEMID                = 0x08
)

// Suboption codes for OptionIP.
const (
	SubIPMAC         = 0x01
	SubIPParameter   = 0x02
	SubIPFullIPSuite = 0x03
)

// MinDCPHeaderLen is the smallest meaningful DCP RT header.
const MinDCPHeaderLen = 10

// Wire errors.
var (
	ErrShortDCP        = errors.New("profinet: DCP frame too short")
	ErrShortBlock      = errors.New("profinet: DCP block truncated")
	ErrUnknownService  = errors.New("profinet: unknown DCP service id")
	ErrBlockLengthZero = errors.New("profinet: DCP block length 0")
)

// Header is the parsed DCP RT header (everything between the
// Ethernet header and the first TLV block).
type Header struct {
	FrameID       uint16
	ServiceID     uint8
	ServiceType   uint8
	XID           uint32
	ReservedDelay uint16
	DataLength    uint16
}

// Block is one TLV entry inside the DCP data area.
type Block struct {
	Option    uint8
	Suboption uint8
	Length    uint16
	BlockInfo uint16
	// Data excludes BlockInfo (the first 2 bytes of the
	// claimed Length are BlockInfo by convention).
	Data []byte
}

// Frame is the parsed DCP frame (header + blocks). Use
// DecodeDCP to construct.
type Frame struct {
	Header Header
	Blocks []Block
}

// DecodeDCP parses a buffer containing the DCP RT frame
// (everything AFTER the Ethernet header). Caller is
// responsible for stripping the 14-byte Ethernet header (or
// 18 bytes if there's a VLAN tag).
func DecodeDCP(buf []byte) (*Frame, error) {
	if len(buf) < MinDCPHeaderLen {
		return nil, fmt.Errorf("%w: %d bytes (need %d)", ErrShortDCP, len(buf), MinDCPHeaderLen)
	}
	f := &Frame{
		Header: Header{
			FrameID:       binary.BigEndian.Uint16(buf[0:2]),
			ServiceID:     buf[2],
			ServiceType:   buf[3],
			XID:           binary.BigEndian.Uint32(buf[4:8]),
			ReservedDelay: binary.BigEndian.Uint16(buf[8:10]),
		},
	}
	if len(buf) < 12 {
		return f, nil
	}
	f.Header.DataLength = binary.BigEndian.Uint16(buf[10:12])
	dataEnd := 12 + int(f.Header.DataLength)
	if dataEnd > len(buf) {
		dataEnd = len(buf) // tolerate truncation; surfaces in caller
	}
	blocks, err := decodeBlocks(buf[12:dataEnd])
	if err != nil {
		return f, err // partial result still useful
	}
	f.Blocks = blocks
	return f, nil
}

// decodeBlocks walks the TLV stream. Each block is at least
// 6 bytes (option+sub+length+info); padding to even-length
// boundary is consumed transparently.
func decodeBlocks(buf []byte) ([]Block, error) {
	var out []Block
	cursor := 0
	for cursor < len(buf) {
		if cursor+6 > len(buf) {
			return out, fmt.Errorf("%w: header at offset %d", ErrShortBlock, cursor)
		}
		b := Block{
			Option:    buf[cursor],
			Suboption: buf[cursor+1],
			Length:    binary.BigEndian.Uint16(buf[cursor+2 : cursor+4]),
			BlockInfo: binary.BigEndian.Uint16(buf[cursor+4 : cursor+6]),
		}
		if b.Length < 2 {
			return out, fmt.Errorf("%w: option=%d sub=%d", ErrBlockLengthZero, b.Option, b.Suboption)
		}
		// Block "Length" includes the 2-byte BlockInfo. Data
		// payload follows.
		dataLen := int(b.Length) - 2
		dataStart := cursor + 6
		dataEnd := dataStart + dataLen
		if dataEnd > len(buf) {
			return out, fmt.Errorf("%w: data overruns at offset %d (want %d, have %d)",
				ErrShortBlock, cursor, dataEnd, len(buf))
		}
		b.Data = append([]byte(nil), buf[dataStart:dataEnd]...)
		out = append(out, b)
		// Advance + pad to even alignment.
		cursor = dataEnd
		if cursor%2 != 0 && cursor < len(buf) {
			cursor++
		}
	}
	return out, nil
}

// EncodeDCPIdentifyAll builds a DCP Identify request that
// matches every device on the segment ("all options"). XID
// is operator-supplied so a sniffer can correlate responses.
//
// Returns the bytes AFTER the Ethernet header (caller adds
// the 14-byte MAC frame). One TLV block: Option=All (0xFF),
// Suboption=All (0xFF), Length=2, BlockInfo=0.
func EncodeDCPIdentifyAll(xid uint32) []byte {
	// 12-byte header + 6-byte block + 0 data + no padding = 18.
	out := make([]byte, 18)
	binary.BigEndian.PutUint16(out[0:2], FrameIDIdentifyRequest)
	out[2] = ServiceIdentify
	out[3] = ServiceTypeRequest
	binary.BigEndian.PutUint32(out[4:8], xid)
	binary.BigEndian.PutUint16(out[8:10], 0x0001) // ResponseDelay=1 (10ms)
	binary.BigEndian.PutUint16(out[10:12], 6)     // DCPDataLength
	out[12] = OptionAll
	out[13] = OptionAll
	binary.BigEndian.PutUint16(out[14:16], 2) // BlockLength
	binary.BigEndian.PutUint16(out[16:18], 0) // BlockInfo
	return out
}

// IdentifyResponse is a flattened summary of an Identify-
// response frame's blocks. Operators want NameOfStation /
// DeviceID / Role / IP at a glance.
type IdentifyResponse struct {
	NameOfStation string
	VendorID      uint16
	DeviceID      uint16
	DeviceRole    uint8
	OEMDeviceID   string
	IP            net.IP
	Subnet        net.IP
	Gateway       net.IP
}

// ParseIdentifyResponse walks `f`'s blocks and fills the
// IdentifyResponse fields. Missing options leave zero values.
func ParseIdentifyResponse(f *Frame) IdentifyResponse {
	var r IdentifyResponse
	for _, b := range f.Blocks {
		switch b.Option {
		case OptionDevice:
			r.applyDeviceBlock(b)
		case OptionIP:
			r.applyIPBlock(b)
		}
	}
	return r
}

func (r *IdentifyResponse) applyDeviceBlock(b Block) {
	switch b.Suboption {
	case SubDeviceNameOfStation:
		r.NameOfStation = printableASCII(b.Data)
	case SubDeviceID:
		if len(b.Data) >= 4 {
			r.VendorID = binary.BigEndian.Uint16(b.Data[0:2])
			r.DeviceID = binary.BigEndian.Uint16(b.Data[2:4])
		}
	case SubDeviceRole:
		if len(b.Data) >= 1 {
			r.DeviceRole = b.Data[0]
		}
	case SubDeviceOEMID:
		if len(b.Data) >= 4 {
			r.OEMDeviceID = fmt.Sprintf("%02x%02x:%02x%02x",
				b.Data[0], b.Data[1], b.Data[2], b.Data[3])
		}
	}
}

func (r *IdentifyResponse) applyIPBlock(b Block) {
	if b.Suboption == SubIPParameter && len(b.Data) >= 12 {
		r.IP = net.IP(append([]byte(nil), b.Data[0:4]...))
		r.Subnet = net.IP(append([]byte(nil), b.Data[4:8]...))
		r.Gateway = net.IP(append([]byte(nil), b.Data[8:12]...))
	}
}

// printableASCII strips non-printable bytes from a name
// payload. PROFINET station names are ASCII per IEC 61158;
// real-world devices occasionally pad with NULs.
func printableASCII(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			out = append(out, c)
		}
	}
	return string(out)
}

// FormatDeviceRole renders the 1-byte role bitfield as text.
// Bits: 0=IO-Controller, 1=IO-Device, 2=IO-Multidevice,
// 3=PNIO-Supervisor.
func FormatDeviceRole(role uint8) string {
	if role == 0 {
		return "none"
	}
	parts := []string{}
	if role&0x01 != 0 {
		parts = append(parts, "IO-Controller")
	}
	if role&0x02 != 0 {
		parts = append(parts, "IO-Device")
	}
	if role&0x04 != 0 {
		parts = append(parts, "IO-Multidevice")
	}
	if role&0x08 != 0 {
		parts = append(parts, "PNIO-Supervisor")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("unknown(0x%02x)", role)
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "+" + p
	}
	return out
}
