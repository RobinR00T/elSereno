package wire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// linkFrame returns the header and on-wire body of a frame with the
// given control octet, addresses and user data, with correct CRCs.
func linkFrame(ctrl uint8, dest, src uint16, userData []byte) (hdr, body []byte) {
	hdr = []byte{StartBytes[0], StartBytes[1], uint8(5 + len(userData)), ctrl, 0, 0, 0, 0, 0, 0} // #nosec G115 -- test data under 250 octets
	binary.LittleEndian.PutUint16(hdr[4:6], dest)
	binary.LittleEndian.PutUint16(hdr[6:8], src)
	binary.LittleEndian.PutUint16(hdr[8:10], CRC16(hdr[0:8]))
	return hdr, AppendBlockCRCs(userData)
}

// directOperateTrip is the user data of a Direct Operate of one CROB
// (g12v1, qualifier 0x17, index 7, TRIP + PULSE_ON 0x81): transport
// FIR|FIN, application FIR|FIN, FC 5.
var directOperateTrip = []byte{
	0xC0, 0xC0, 0x05,
	0x0C, 0x01, 0x17, 0x01, 0x07,
	0x81, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
}

// TestCheckToOutstation walks the stateless rows of AN2013-004b Table 1
// that apply to a frame travelling toward an outstation.
func TestCheckToOutstation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		ctrl  uint8
		dest  uint16
		src   uint16
		data  []byte
		valid bool
	}{
		{"Request Link Status", 0xC9, 1, 0, nil, true},
		{"Test Link States FCB=0", 0xD2, 1, 0, nil, true},
		{"Test Link States FCB=1", 0xF2, 1, 0, nil, true},
		{"Reset Link States", 0xC0, 1, 0, nil, true},
		{"Unconfirmed User Data", 0xC4, 1, 0, directOperateTrip, true},
		{"Confirmed User Data", 0xD3, 1, 0, directOperateTrip, true},
		{"secondary ACK", 0x80, 1, 0, nil, true},
		{"secondary ACK with DFC", 0x90, 1, 0, nil, true},
		{"secondary NACK", 0x81, 1, 0, nil, true},
		{"secondary LINK_STATUS", 0x8B, 1, 0, nil, true},
		{"secondary NOT_SUPPORTED", 0x8F, 1, 0, nil, true},
		{"self address 0xFFFC (device-dependent, not checked)", 0xC9, 0xFFFC, 0, nil, true},
		{"user data to broadcast", 0xC4, 0xFFFD, 0, directOperateTrip, true},

		// PITF-081: the frames the proxies forwarded before 2026-10-14.
		{"secondary FC 4 carrying a Direct Operate", 0x84, 1, 0, directOperateTrip, false},
		{"secondary FC 4 header-only", 0x84, 1, 0, nil, false},
		{"secondary FC 4 with DIR=0", 0x04, 1, 0, directOperateTrip, false},
		{"secondary LINK_STATUS carrying data", 0x8B, 1, 0, directOperateTrip, false},
		{"Request Link Status carrying data", 0xC9, 1, 0, directOperateTrip, false},
		{"Test Link States carrying data", 0xD2, 1, 0, directOperateTrip, false},
		{"Reset Link States carrying data", 0xC0, 1, 0, directOperateTrip, false},

		{"Reset of User Process (removed in 1815-2012)", 0xC1, 1, 0, nil, false},
		{"Test Link States with FCV=0", 0xC2, 1, 0, nil, false},
		{"Confirmed User Data with FCV=0", 0xC3, 1, 0, directOperateTrip, false},
		{"Unconfirmed User Data with FCV=1", 0xD4, 1, 0, directOperateTrip, false},
		{"Request Link Status with FCV=1", 0xD9, 1, 0, nil, false},
		{"undefined primary function 7", 0xC7, 1, 0, nil, false},
		{"undefined secondary function 2", 0x82, 1, 0, nil, false},
		{"secondary with the FCB position set", 0xA0, 1, 0, nil, false},
		{"user data without data", 0xC4, 1, 0, nil, false},
		{"reserved destination 0xFFF0", 0xC9, 0xFFF0, 0, nil, false},
		{"reserved destination 0xFFFB", 0xC9, 0xFFFB, 0, nil, false},
		{"Request Link Status to broadcast", 0xC9, 0xFFFF, 0, nil, false},
		{"secondary ACK to broadcast", 0x80, 0xFFFE, 0, nil, false},
		{"reserved source 0xFFF0", 0xC9, 1, 0xFFF0, nil, false},
		{"reserved source 0xFFFF", 0xC4, 1, 0xFFFF, directOperateTrip, false},
	}
	for _, c := range cases {
		hdr, body := linkFrame(c.ctrl, c.dest, c.src, c.data)
		h, err := ParseCheckedHeader(hdr)
		if err != nil {
			t.Fatalf("%s: ParseCheckedHeader: %v", c.name, err)
		}
		got, err := CheckToOutstation(h, body)
		if c.valid {
			if err != nil {
				t.Errorf("%s: ctrl 0x%02x rejected: %v", c.name, c.ctrl, err)
				continue
			}
			if !bytes.Equal(got, c.data) {
				t.Errorf("%s: user data % x, want % x", c.name, got, c.data)
			}
			continue
		}
		if !errors.Is(err, ErrInvalidFrame) {
			t.Errorf("%s: ctrl 0x%02x dest 0x%04x src 0x%04x accepted, want ErrInvalidFrame", c.name, c.ctrl, c.dest, c.src)
		}
	}
}

func TestCheckToOutstation_BadBlockCRC(t *testing.T) {
	t.Parallel()
	hdr, body := linkFrame(0xC4, 1, 0, directOperateTrip)
	body[len(body)-1] ^= 0xFF
	h, err := ParseCheckedHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckToOutstation(h, body); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("bad block CRC accepted: %v", err)
	}
}

// TestReadFrame_Resync: octets that do not start a valid header (noise,
// a header with a bad CRC, wrong start octets) are skipped one at a time
// until a valid header, as AN2013-004b prescribes after a discard.
func TestReadFrame_Resync(t *testing.T) {
	t.Parallel()
	badCRC := BuildRequestLinkStatus(1, 0)
	badCRC[8] ^= 0x01
	hdr, body := linkFrame(0xC4, 1, 0, directOperateTrip)
	var in []byte
	in = append(in, 0xFF, 0x05, 0x64, 0x00) // noise, a lone start pair, LENGTH 0
	in = append(in, badCRC...)
	in = append(in, hdr...)
	in = append(in, body...)
	in = append(in, BuildRequestLinkStatus(2, 0)...)
	r := bufio.NewReader(bytes.NewReader(in))

	h, gotHdr, gotBody, skipped, err := ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	if want := 4 + HeaderLen; skipped != want {
		t.Fatalf("skipped %d octets, want %d", skipped, want)
	}
	if h.Control != 0xC4 || !bytes.Equal(gotHdr, hdr) || !bytes.Equal(gotBody, body) {
		t.Fatalf("got ctrl 0x%02x hdr % x body % x", h.Control, gotHdr, gotBody)
	}
	h, _, gotBody, skipped, err = ReadFrame(r)
	if err != nil || skipped != 0 || h.Dest != 2 || len(gotBody) != 0 {
		t.Fatalf("second frame: dest %d body %d skipped %d err %v", h.Dest, len(gotBody), skipped, err)
	}
	if _, _, _, _, err = ReadFrame(r); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: got %v, want EOF", err)
	}
}

func TestParseCheckedHeader_BadCRC(t *testing.T) {
	t.Parallel()
	hdr := BuildRequestLinkStatus(1, 0)
	hdr[8] ^= 0x01
	if _, err := ParseCheckedHeader(hdr); !errors.Is(err, ErrHeaderCRC) {
		t.Fatalf("got %v, want ErrHeaderCRC", err)
	}
	if ValidHeader(hdr) {
		t.Fatal("ValidHeader accepted a bad header CRC")
	}
}

// FuzzCheckToOutstation: no panic on any input, and a frame that passes
// is header-only unless it is user data (the property PITF-081 broke).
func FuzzCheckToOutstation(f *testing.F) {
	hdr, body := linkFrame(0xC4, 1, 0, directOperateTrip)
	f.Add(append(hdr, body...))
	hdr, body = linkFrame(0x84, 1, 0, directOperateTrip)
	f.Add(append(hdr, body...))
	f.Add(BuildRequestLinkStatus(1, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := ParseCheckedHeader(b)
		if err != nil {
			return
		}
		rest := b[HeaderLen:]
		if n := BodyLen(h.Length); len(rest) > n {
			rest = rest[:n]
		}
		data, err := CheckToOutstation(h, rest)
		if err != nil {
			return
		}
		if !IsUserData(h.Control) && (h.Length != 5 || data != nil) {
			t.Fatalf("control 0x%02x passed with length %d", h.Control, h.Length)
		}
		if IsUserData(h.Control) && len(data) != int(h.Length)-5 {
			t.Fatalf("user data %d octets, length %d", len(data), h.Length)
		}
	})
}
