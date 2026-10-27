package pcapfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// MaxFileSize caps what ReadUDP loads into memory.
const MaxFileSize = 256 << 20

// Errors.
var (
	ErrFormat   = errors.New("pcapfile: not a pcap or pcapng file")
	ErrTooLarge = errors.New("pcapfile: capture larger than the limit")
)

// Link types.
const (
	linkNull     = 0
	linkEthernet = 1
	linkRaw      = 101
	linkIPv4     = 228
	linkIPv6     = 229
)

// Datagram is one UDP datagram found in a capture.
type Datagram struct {
	Time    time.Time
	Src     netip.AddrPort
	Dst     netip.AddrPort
	Payload []byte
}

// packet is one captured frame and its link type.
type packet struct {
	ts   time.Time
	link uint32
	data []byte
}

// ReadUDP reads a whole capture and returns its UDP datagrams in file
// order. Frames that are not UDP, or not decodable, are skipped.
func ReadUDP(r io.Reader) ([]Datagram, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("pcapfile: read: %w", err)
	}
	if len(b) > MaxFileSize {
		return nil, ErrTooLarge
	}
	pkts, err := packets(b)
	if err != nil {
		return nil, err
	}
	var out []Datagram
	for _, p := range pkts {
		if d, ok := udpFromLink(p.link, p.data); ok {
			d.Time = p.ts
			out = append(out, d)
		}
	}
	return out, nil
}

// packets splits a capture into frames.
func packets(b []byte) ([]packet, error) {
	if len(b) < 4 {
		return nil, ErrFormat
	}
	switch binary.LittleEndian.Uint32(b) {
	case 0x0A0D0D0A:
		return pcapng(b)
	case 0xA1B2C3D4, 0xA1B23C4D:
		return classic(b, binary.LittleEndian)
	case 0xD4C3B2A1, 0x4D3CB2A1:
		return classic(b, binary.BigEndian)
	}
	return nil, ErrFormat
}

// classic reads a libpcap file in byte order bo.
func classic(b []byte, bo binary.ByteOrder) ([]packet, error) {
	if len(b) < 24 {
		return nil, ErrFormat
	}
	nano := bo.Uint32(b) == 0xA1B23C4D
	link := bo.Uint32(b[20:24]) & 0x0FFFFFFF
	var out []packet
	for off := 24; off+16 <= len(b); {
		sec, frac := bo.Uint32(b[off:]), bo.Uint32(b[off+4:])
		incl := int(bo.Uint32(b[off+8:]))
		off += 16
		if incl < 0 || incl > len(b)-off {
			break // truncated last record
		}
		ns := int64(frac) * 1000
		if nano {
			ns = int64(frac)
		}
		out = append(out, packet{time.Unix(int64(sec), ns).UTC(), link, b[off : off+incl]})
		off += incl
	}
	return out, nil
}

// pcapng reads a pcapng file: Section Header, Interface Description,
// Enhanced Packet and Simple Packet blocks; other blocks are skipped.
func pcapng(b []byte) ([]packet, error) {
	var (
		bo    binary.ByteOrder = binary.LittleEndian
		links []iface
		out   []packet
	)
	for off := 0; off+12 <= len(b); {
		if binary.LittleEndian.Uint32(b[off:]) == 0x0A0D0D0A {
			bo = shbByteOrder(b[off:])
			links = links[:0]
		}
		typ, blen := bo.Uint32(b[off:]), int(bo.Uint32(b[off+4:]))
		if blen < 12 || blen%4 != 0 || blen > len(b)-off {
			break
		}
		body := b[off+8 : off+blen-4]
		switch typ {
		case 1: // Interface Description
			if len(body) >= 8 {
				links = append(links, iface{uint32(bo.Uint16(body)), tsUnits(body[8:], bo)})
			}
		case 6: // Enhanced Packet
			if p, ok := enhanced(body, bo, links); ok {
				out = append(out, p)
			}
		case 3: // Simple Packet: interface 0, no timestamp
			if p, ok := simplePacket(body, bo, links); ok {
				out = append(out, p)
			}
		}
		off += blen
	}
	if len(out) == 0 && len(links) == 0 {
		return nil, ErrFormat
	}
	return out, nil
}

// shbByteOrder returns the byte order a Section Header Block declares
// via its magic; little-endian when the magic is absent or short.
func shbByteOrder(b []byte) binary.ByteOrder {
	if len(b) >= 12 && binary.LittleEndian.Uint32(b[8:]) == 0x1A2B3C4D {
		return binary.LittleEndian
	}
	return binary.BigEndian
}

// simplePacket decodes a pcapng Simple Packet Block (interface 0, no
// timestamp). It reports ok=false when the block is short or no
// interface has been seen yet.
func simplePacket(body []byte, bo binary.ByteOrder, links []iface) (packet, bool) {
	if len(body) < 4 || len(links) == 0 {
		return packet{}, false
	}
	n := min(int(bo.Uint32(body)), len(body)-4)
	return packet{link: links[0].link, data: body[4 : 4+n]}, true
}

// iface is one pcapng Interface Description: its link type and how many
// timestamp units make one second (if_tsresol; 1e6 by default).
type iface struct {
	link   uint32
	perSec uint64
}

// tsUnits reads if_tsresol (option 9) from the IDB options. A decimal
// exponent 0..9 or a binary exponent 0..30 is honoured; anything else
// keeps the microsecond default.
func tsUnits(opts []byte, bo binary.ByteOrder) uint64 {
	for len(opts) >= 4 {
		code, n := bo.Uint16(opts), int(bo.Uint16(opts[2:]))
		if code == 0 || 4+n > len(opts) {
			break
		}
		if code == 9 && n >= 1 {
			v := opts[4]
			switch {
			case v&0x80 == 0 && v <= 9:
				u := uint64(1)
				for range v {
					u *= 10
				}
				return u
			case v&0x80 != 0 && v&0x7f <= 30:
				return 1 << (v & 0x7f)
			}
		}
		opts = opts[4+(n+3)&^3:]
	}
	return 1_000_000
}

// enhanced decodes an Enhanced Packet Block body.
func enhanced(body []byte, bo binary.ByteOrder, links []iface) (packet, bool) {
	if len(body) < 20 {
		return packet{}, false
	}
	ifc := int(bo.Uint32(body))
	if ifc >= len(links) {
		return packet{}, false
	}
	ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
	capLen := int(bo.Uint32(body[12:]))
	if capLen < 0 || capLen > len(body)-20 {
		return packet{}, false
	}
	u := links[ifc].perSec
	t := time.Unix(int64(ts/u), int64((ts%u)*1_000_000_000/u)).UTC() // #nosec G115 -- capture timestamps fit int64; u <= 2^30
	return packet{t, links[ifc].link, body[20 : 20+capLen]}, true
}
