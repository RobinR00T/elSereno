package pcapfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// ipv4UDP builds an IPv4+UDP packet 192.0.2.1:40000 -> 192.0.2.2:1502.
func ipv4UDP(payload []byte) []byte {
	u := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], 40000)
	binary.BigEndian.PutUint16(u[2:], 1502)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload))) // #nosec G115 -- test fixture, payload lengths are bounded
	u = append(u, payload...)
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(u))) // #nosec G115 -- test fixture, payload lengths are bounded
	return append(ip, u...)
}

func ipv6UDP(payload []byte) []byte {
	u := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], 40000)
	binary.BigEndian.PutUint16(u[2:], 1502)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload))) // #nosec G115 -- test fixture, payload lengths are bounded
	u = append(u, payload...)
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(u))) // #nosec G115 -- test fixture, payload lengths are bounded
	ip[6] = 17
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::2").As16()
	copy(ip[8:], src[:])
	copy(ip[24:], dst[:])
	return append(ip, u...)
}

func ethernet(vlan bool, ip []byte) []byte {
	f := make([]byte, 12)
	if vlan {
		f = append(f, 0x81, 0x00, 0x00, 0x0a)
	}
	f = append(f, 0x08, 0x00)
	return append(f, ip...)
}

func classicFile(link uint32, frames ...[]byte) []byte {
	var b bytes.Buffer
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h, 0xA1B2C3D4)
	binary.LittleEndian.PutUint32(h[20:], link)
	b.Write(h)
	for i, f := range frames {
		r := make([]byte, 16)
		binary.LittleEndian.PutUint32(r, uint32(1700000000+i))
		binary.LittleEndian.PutUint32(r[8:], uint32(len(f)))  // #nosec G115 -- test fixture, payload lengths are bounded
		binary.LittleEndian.PutUint32(r[12:], uint32(len(f))) // #nosec G115 -- test fixture, payload lengths are bounded
		b.Write(r)
		b.Write(f)
	}
	return b.Bytes()
}

func block(typ uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	n := uint32(12 + len(body)) // #nosec G115 -- test fixture, payload lengths are bounded
	b := binary.LittleEndian.AppendUint32(nil, typ)
	b = binary.LittleEndian.AppendUint32(b, n)
	b = append(b, body...)
	return binary.LittleEndian.AppendUint32(b, n)
}

func pcapngFile(link uint16, frames ...[]byte) []byte {
	shb := binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)
	shb = append(shb, 1, 0, 0, 0)
	shb = append(shb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	out := block(0x0A0D0D0A, shb)
	idb := binary.LittleEndian.AppendUint16(nil, link)
	idb = append(idb, 0, 0, 0, 0, 0, 0)
	out = append(out, block(1, idb)...)
	for _, f := range frames {
		epb := make([]byte, 20)
		binary.LittleEndian.PutUint32(epb[12:], uint32(len(f))) // #nosec G115 -- test fixture, payload lengths are bounded
		binary.LittleEndian.PutUint32(epb[16:], uint32(len(f))) // #nosec G115 -- test fixture, payload lengths are bounded
		epb = append(epb, f...)
		out = append(out, block(6, epb)...)
	}
	return out
}

func TestReadUDP_Formats(t *testing.T) {
	payload := []byte{1, 0, 0, 0, 1, 0xfc}
	cases := map[string][]byte{
		"classic-ethernet": classicFile(linkEthernet, ethernet(false, ipv4UDP(payload))),
		"classic-vlan":     classicFile(linkEthernet, ethernet(true, ipv4UDP(payload))),
		"classic-raw-ipv6": classicFile(linkRaw, ipv6UDP(payload)),
		"pcapng-ethernet":  pcapngFile(linkEthernet, ethernet(false, ipv4UDP(payload))),
		"pcapng-null":      pcapngFile(linkNull, append([]byte{2, 0, 0, 0}, ipv4UDP(payload)...)),
	}
	for name, file := range cases {
		t.Run(name, func(t *testing.T) {
			ds, err := ReadUDP(bytes.NewReader(file))
			if err != nil {
				t.Fatal(err)
			}
			if len(ds) != 1 || !bytes.Equal(ds[0].Payload, payload) || ds[0].Dst.Port() != 1502 {
				t.Fatalf("datagrams = %+v", ds)
			}
		})
	}
}

func TestReadUDP_SkipsAndErrors(t *testing.T) {
	tcp := ipv4UDP([]byte{9})
	tcp[9] = 6
	ds, err := ReadUDP(bytes.NewReader(classicFile(linkEthernet, ethernet(false, tcp), []byte{1, 2})))
	if err != nil || len(ds) != 0 {
		t.Errorf("non-UDP frames: %v %v", ds, err)
	}
	if _, err := ReadUDP(bytes.NewReader([]byte("not a capture"))); !errors.Is(err, ErrFormat) {
		t.Errorf("garbage: %v", err)
	}
	// A truncated last record is dropped, not an error.
	f := classicFile(linkEthernet, ethernet(false, ipv4UDP([]byte{7})))
	if ds, err := ReadUDP(bytes.NewReader(f[:len(f)-3])); err != nil || len(ds) != 0 {
		t.Errorf("truncated: %v %v", ds, err)
	}
}

func FuzzReadUDP(f *testing.F) {
	f.Add(classicFile(linkEthernet, ethernet(true, ipv4UDP([]byte{1, 2, 3}))))
	f.Add(pcapngFile(linkEthernet, ethernet(false, ipv6UDP([]byte{4}))))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = ReadUDP(bytes.NewReader(b))
	})
}

func TestPcapngTsresol(t *testing.T) {
	f := pcapngFile(linkEthernet, ethernet(false, ipv4UDP([]byte{1})))
	// Rebuild the IDB with if_tsresol = 9 (nanoseconds).
	idb := binary.LittleEndian.AppendUint16(nil, linkEthernet)
	idb = append(idb, 0, 0, 0, 0, 0, 0, 9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0)
	shbLen := int(binary.LittleEndian.Uint32(f[4:]))
	oldIDB := int(binary.LittleEndian.Uint32(f[shbLen+4:]))
	epb := append([]byte(nil), f[shbLen+oldIDB:]...)
	// timestamp 1.5 s in ns: high 0, low 1_500_000_000
	binary.LittleEndian.PutUint32(epb[8+8:], 1_500_000_000)
	out := append(append(append([]byte(nil), f[:shbLen]...), block(1, idb)...), epb...)
	ds, err := ReadUDP(bytes.NewReader(out))
	if err != nil || len(ds) != 1 {
		t.Fatalf("%v %v", ds, err)
	}
	if got := ds[0].Time.UnixMilli(); got != 1500 {
		t.Fatalf("time = %d ms, want 1500", got)
	}
	if tsUnits([]byte{9, 0, 1, 0, 0x83, 0, 0, 0}, binary.LittleEndian) != 8 {
		t.Error("binary tsresol")
	}
}
