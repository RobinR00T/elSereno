package pcapfile

import (
	"encoding/binary"
	"net/netip"
)

// udpFromLink strips the link header and decodes IPv4/IPv6 + UDP.
func udpFromLink(link uint32, f []byte) (Datagram, bool) {
	switch link {
	case linkEthernet:
		if len(f) < 14 {
			return Datagram{}, false
		}
		et, off := binary.BigEndian.Uint16(f[12:14]), 14
		for et == 0x8100 || et == 0x88A8 { // 802.1Q / 802.1ad tags
			if len(f) < off+4 {
				return Datagram{}, false
			}
			et, off = binary.BigEndian.Uint16(f[off+2:off+4]), off+4
		}
		return udpFromIP(f[off:])
	case linkRaw, linkIPv4, linkIPv6:
		return udpFromIP(f)
	case linkNull:
		if len(f) < 4 {
			return Datagram{}, false
		}
		return udpFromIP(f[4:])
	}
	return Datagram{}, false
}

// udpFromIP decodes an IPv4 or IPv6 packet carrying UDP.
func udpFromIP(p []byte) (Datagram, bool) {
	if len(p) < 1 {
		return Datagram{}, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return Datagram{}, false
		}
		ihl := int(p[0]&0x0F) * 4
		if ihl < 20 || len(p) < ihl || p[9] != 17 {
			return Datagram{}, false
		}
		if binary.BigEndian.Uint16(p[6:8])&0x1FFF != 0 {
			return Datagram{}, false // non-first fragment
		}
		src, _ := netip.AddrFromSlice(p[12:16])
		dst, _ := netip.AddrFromSlice(p[16:20])
		return udp(p[ihl:], src, dst)
	case 6:
		if len(p) < 40 || p[6] != 17 {
			return Datagram{}, false
		}
		src, _ := netip.AddrFromSlice(p[8:24])
		dst, _ := netip.AddrFromSlice(p[24:40])
		return udp(p[40:], src, dst)
	}
	return Datagram{}, false
}

// udp decodes the UDP header; the payload is bounded by the UDP length.
func udp(u []byte, src, dst netip.Addr) (Datagram, bool) {
	if len(u) < 8 {
		return Datagram{}, false
	}
	n := int(binary.BigEndian.Uint16(u[4:6]))
	if n < 8 || n > len(u) {
		return Datagram{}, false
	}
	return Datagram{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(u[0:2])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(u[2:4])),
		Payload: u[8:n],
	}, true
}
