package goose_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/goose"
)

// ---- GOOSE frame builder --------------------------------------------

type gooseFields struct {
	appID            uint16
	gocbRef          string
	goID             string
	datSet           string
	ttl              uint32
	stNum            uint32
	sqNum            uint32
	test             bool
	testPresent      bool
	confRev          uint32
	ndsCom           bool
	ndsComPresent    bool
	numDatSetEntries uint32
	vlan             bool
	vlanID           uint16
}

// berInt encodes v as a minimal big-endian BER INTEGER value.
func berInt(v uint32) []byte {
	if v == 0 {
		return []byte{0x00}
	}
	var full [4]byte
	binary.BigEndian.PutUint32(full[:], v)
	i := 0
	for i < 3 && full[i] == 0 {
		i++
	}
	return full[i:]
}

func tlv(tag byte, val []byte) []byte {
	if len(val) > 127 {
		panic("test builder only emits short-form lengths")
	}
	return append([]byte{tag, byte(len(val))}, val...) // #nosec G115 -- bounded < 128 above
}

func buildGooseFrame(f gooseFields) []byte {
	var apduBody []byte
	add := func(tag byte, val []byte) { apduBody = append(apduBody, tlv(tag, val)...) }
	if f.gocbRef != "" {
		add(0x80, []byte(f.gocbRef))
	}
	add(0x81, berInt(f.ttl))
	if f.datSet != "" {
		add(0x82, []byte(f.datSet))
	}
	if f.goID != "" {
		add(0x83, []byte(f.goID))
	}
	add(0x84, make([]byte, 8)) // timestamp
	add(0x85, berInt(f.stNum))
	add(0x86, berInt(f.sqNum))
	if f.testPresent {
		b := byte(0)
		if f.test {
			b = 0xFF
		}
		add(0x87, []byte{b})
	}
	add(0x88, berInt(f.confRev))
	if f.ndsComPresent {
		b := byte(0)
		if f.ndsCom {
			b = 0xFF
		}
		add(0x89, []byte{b})
	}
	add(0x8A, berInt(f.numDatSetEntries))

	apdu := tlv(0x61, apduBody)

	// GOOSE header: APPID, Length, Reserved1, Reserved2.
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], f.appID)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(8+len(apdu))) // #nosec G115 -- test frames are small
	payload := make([]byte, 0, len(hdr)+len(apdu))
	payload = append(payload, hdr...)
	payload = append(payload, apdu...)

	return wrapEthernet(goose.EtherTypeGOOSE, payload, f.vlan, f.vlanID)
}

func wrapEthernet(etherType uint16, payload []byte, vlan bool, vlanID uint16) []byte {
	frame := make([]byte, 0, 18+len(payload))
	frame = append(frame, 0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01) // dst (GOOSE multicast)
	frame = append(frame, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55) // src
	if vlan {
		frame = append(frame, 0x81, 0x00)
		var tci [2]byte
		binary.BigEndian.PutUint16(tci[:], vlanID&0x0FFF)
		frame = append(frame, tci[:]...)
	}
	var et [2]byte
	binary.BigEndian.PutUint16(et[:], etherType)
	frame = append(frame, et[:]...)
	return append(frame, payload...)
}

// ---- tests ----------------------------------------------------------

func TestDissectGoose(t *testing.T) {
	frame := buildGooseFrame(gooseFields{
		appID: 0x0001, gocbRef: "IED1/LLN0$GO$gcb", goID: "trip", datSet: "IED1/LLN0$DS",
		ttl: 2000, stNum: 7, sqNum: 3, confRev: 1, numDatSetEntries: 4,
		testPresent: true, test: false,
	})
	f, err := goose.Dissect(frame)
	if err != nil {
		t.Fatalf("Dissect: %v", err)
	}
	if f.Kind != goose.KindGOOSE || f.Goose == nil {
		t.Fatalf("kind=%v goose=%v", f.Kind, f.Goose)
	}
	g := f.Goose
	if g.APPID != 0x0001 || g.GoID != "trip" || g.GocbRef != "IED1/LLN0$GO$gcb" {
		t.Errorf("identity wrong: %+v", g)
	}
	if g.StNum != 7 || g.SqNum != 3 || g.ConfRev != 1 || g.TimeAllowedToLive != 2000 {
		t.Errorf("counters wrong: %+v", g)
	}
	if g.NumDatSetEntries != 4 {
		t.Errorf("numDatSetEntries = %d, want 4", g.NumDatSetEntries)
	}
}

func TestDissectGooseVLAN(t *testing.T) {
	frame := buildGooseFrame(gooseFields{appID: 0x1000, goID: "g", ttl: 100, stNum: 1, sqNum: 0, vlan: true, vlanID: 42})
	f, err := goose.Dissect(frame)
	if err != nil {
		t.Fatalf("Dissect VLAN: %v", err)
	}
	if !f.VLAN || f.VLANID != 42 {
		t.Errorf("VLAN not parsed: vlan=%t id=%d", f.VLAN, f.VLANID)
	}
	if f.Goose.StNum != 1 {
		t.Errorf("stNum=%d, want 1", f.Goose.StNum)
	}
}

func TestDissectNotSubstation(t *testing.T) {
	frame := wrapEthernet(0x0800, make([]byte, 20), false, 0) // IPv4
	if _, err := goose.Dissect(frame); !errors.Is(err, goose.ErrNotSubstation) {
		t.Fatalf("err = %v, want ErrNotSubstation", err)
	}
}

func TestDissectTooShort(t *testing.T) {
	if _, err := goose.Dissect([]byte{0x01, 0x02, 0x03}); !errors.Is(err, goose.ErrTooShort) {
		t.Fatalf("err = %v, want ErrTooShort", err)
	}
}

func FuzzDissect(f *testing.F) {
	f.Add(buildGooseFrame(gooseFields{appID: 1, goID: "g", ttl: 10, stNum: 1}))
	f.Add([]byte{})
	f.Add(make([]byte, 14))
	f.Fuzz(func(_ *testing.T, b []byte) {
		frame, err := goose.Dissect(b)
		if err == nil && frame != nil {
			_ = frame.String()
		}
	})
}
